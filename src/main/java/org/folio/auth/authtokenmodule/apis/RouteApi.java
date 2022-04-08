package org.folio.auth.authtokenmodule.apis;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.openapi.RouterBuilder;

import org.folio.auth.authtokenmodule.PermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.LegacyAccessToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.okapi.common.XOkapiHeaders;

import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.JOSEException;

import org.apache.logging.log4j.LogManager;

import org.folio.tlib.RouterCreator;
import org.folio.tlib.TenantInitHooks;

/**
 * This API class handles any non-filter routes that this module must serve. The filter API calls
 * these routes.
 * @see FilterApi
 */
public class RouteApi extends Api implements RouterCreator, TenantInitHooks {
  private static final String SIGN_TOKEN_PERMISSION = "auth.signtoken";
  private static final String SIGN_REFRESH_TOKEN_PERMISSION = "auth.signrefreshtoken";

  private PermissionsSource permissionsSource;
  private TokenCreator tokenCreator;
  private List<Route> routes;

  /**
   * Constructs the API.
   * @param vertx A reference to the current Vertx object.
   * @param tokenCreator A reference to the TokenCreator object. This object is shared among
   * all Api classes.
   */
  public RouteApi(Vertx vertx, TokenCreator tokenCreator) {
    logger = LogManager.getLogger(RouteApi.class);
    this.tokenCreator = tokenCreator;
    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    permissionsSource = new ModulePermissionsSource(vertx, permLookupTimeout);

    // Set up the routes. Here next will call operation handler defined in createRouter.
    // The filter API is responsible for calling these routes, but we define them here.
    routes = new ArrayList<>();
    routes.add( new Route("/token/sign",
      new String[] { SIGN_TOKEN_PERMISSION }, RoutingContext::next));
    // routes.add(new Route("/refreshtoken",
    //   new String[] { SIGN_REFRESH_TOKEN_PERMISSION }, RoutingContext::next));
    // TODO it is unclear whether the signing permission for the refresh token is needed here.
    routes.add(new Route("/token/refresh",
      new String[] { SIGN_REFRESH_TOKEN_PERMISSION, SIGN_TOKEN_PERMISSION }, RoutingContext::next));
    routes.add(new Route("/_/tenant",
      new String[] {}, RoutingContext::next));
    // TODO Because of the startsWith matching this order matters. Should this be like this? Maybe we should have an exact match.
    routes.add( new Route("/token",
      new String[] { SIGN_TOKEN_PERMISSION }, RoutingContext::next));
  }

  @Override
  public Future<Router> createRouter(Vertx vertx) {
    // Bind the openapi yaml definition with the handler methods defined here.
    return RouterBuilder.create(vertx, "openapi/token-1.0.yaml")
        .map(routerBuilder -> {
          routerBuilder
              .operation("token-legacy")
              .handler(this::handleSignLegacyToken);
          routerBuilder
              .operation("token-refresh")
              .handler(this::handleRefresh);
          // routerBuilder
          //     .operation("refreshtoken")
          //     .handler(this::handleSignRefreshToken);
          routerBuilder
              .operation("token-sign")
              .handler(this::handleSignToken);
          return routerBuilder.createRouter();
        });
  }

  @Override
  public Future<Void> postInit(Vertx vertx, String tenant, JsonObject tenantAttributes) {
    logger.debug("Calling postInit for {}", RouteApi.class.getName());

    if (!tenantAttributes.containsKey("module_to")) {
      return Future.succeededFuture(); // Do nothing for disable
    }

    // Create the datastores needed for the routes associated with this API.
    var refreshTokenStore = new RefreshTokenStore(vertx, tenant);
    var apiTokenStore = new ApiTokenStore(vertx, tenant, tokenCreator);
    return apiTokenStore.createTableIfNotExists()
      .compose(x -> refreshTokenStore.createTableIfNotExists());
  }

  /**
   * Given the current request, attempt to handle the request as a route with an endpoint specified
   * in this class. If the route has been found this method will return true.
   * @param ctx The current http context.
   * @param authToken The auth token in scope for this request.
   * @param moduleTokens An encoded JSON object of module tokens.
   */
  public boolean tryHandleRoute(RoutingContext ctx, String authToken, String moduleTokens) {
    for (Route route : routes) {
      if (route.handleRoute(ctx, authToken, moduleTokens)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Handles two types of token signing requests:
   * 1. AccessToken singing requests
   * 2. DummyToken signing requests.
   *
   * When the request is a DummyToken signing request the request will have a boolean "dummy"
   * property.
   *
   * When the request is an AccessToken singing request it will have a user_id property.
   *
   * The only property that is required and which both of these requests have in common is the
   * sub property.
   */
  private void handleSignToken(RoutingContext ctx) {
    try {
      // X-Okapi-Tenant and X-Okapi-Url are already checked in FilterApi.
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      final String content = ctx.getBodyAsString();
      JsonObject json;
      JsonObject payload;
      json = new JsonObject(content);
      payload = json.getJsonObject("payload");

      logger.debug("Payload to create signed token from is {}", payload.encode());

      // Both types of signing requests (dummy and access) have only this property in common.
      String username = payload.getString("sub");

      var responseObject = new JsonObject();

      // auth 2.0 did not expose the "type" property which is now used internally. But other
      // modules like mod-login aren't aware of this type property. Because of this dummy token
      // singing requests have a boolean which can be checked to distinguish them from regular
      // access token signing requests.
      if (isDummyTokenSigningRequest(payload)) {
        logger.debug("Signing request is for a dummy token");

        var dt = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
        responseObject.put("token", dt.encodeAsJWT(tokenCreator));
      } else {
        logger.debug("Signing request is for an access token");

        String userId = payload.getString("user_id");

        // Generate the access token.
        var at = new AccessToken(tenant, username, userId);
        responseObject.put("accessToken", at.encodeAsJWT(tokenCreator));

        // Generate the refresh token.
        String address = ctx.request().remoteAddress().host();
        var rt = new RefreshToken(tenant, username, userId, address);
        responseObject.put("refreshToken", rt.encodeAsJWE(tokenCreator));

        // Clear the user from the permissions cache.
        permissionsSource.clearCacheUser(userId, tenant);
      }

      logger.debug("Successfully created and signed token");

      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  /**
   * Handles two types of token signing requests:
   * 1. AccessToken singing requests
   * 2. DummyToken signing requests.
   *
   * When the request is a DummyToken signing request the request will have a boolean "dummy"
   * property.
   *
   * When the request is an AccessToken singing request it will have a user_id property.
   *
   * The only property that is required and which both of these requests have in common is the
   * sub property.
   */
  private void handleSignLegacyToken(RoutingContext ctx) {
    try {
      // X-Okapi-Tenant and X-Okapi-Url are already checked in FilterApi.
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      final String content = ctx.getBodyAsString();
      JsonObject json;
      JsonObject payload;
      json = new JsonObject(content);
      payload = json.getJsonObject("payload");

      logger.debug("Payload to create signed token from is {}", payload.encode());

      // Both types of signing requests (dummy and access) have only this property in common.
      String username = payload.getString("sub");
      Token token;

      // auth 2.0 did not expose the "type" property which is now used internally. But other
      // modules like mod-login aren't aware of this type property. Because of this dummy token
      // singing requests have a boolean which can be checked to distinguish them from regular
      // access token signing requests.
      if (isDummyTokenSigningRequest(payload)) {
        logger.debug("Signing request is for a dummy token");

        token = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
      } else {
        logger.debug("Signing request is for an access token");

        String userId = payload.getString("user_id");
        token = new LegacyAccessToken(tenant, username, userId);

        // Clear the user from the permissions cache.
        permissionsSource.clearCacheUser(userId, tenant);
      }

      logger.debug("Successfully created and signed token");

      JsonObject responseObject = new JsonObject().put("token", token.encodeAsJWT(tokenCreator));
      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  // Use to determine the type of signing request.
  private boolean isDummyTokenSigningRequest(JsonObject payload) {
    return payload.getBoolean("dummy", Boolean.FALSE); // True property if present, otherwise false.
  }

  private void handleRefresh(RoutingContext ctx) {
    try {
      String content = ctx.getBodyAsString();
      JsonObject requestJson = new JsonObject(content);
      String encryptedJWE = requestJson.getString("refreshToken");
      var context = new TokenValidationContext(ctx.request(), tokenCreator, encryptedJWE);
      Future<Token> tokenValidationResult = Token.validate(context);

      tokenValidationResult.onFailure(h -> {
        handleTokenValidationFailure(h, ctx);
      });

      tokenValidationResult.onSuccess(token -> {
        String username = token.getClaims().getString("sub");
        String userId = token.getClaims().getString("user_id");
        String tenant = token.getClaims().getString("tenant");

        try {
          // TODO To do RTR we need to return both a new AT and a new RT here.
          String at = new AccessToken(tenant, username, userId).encodeAsJWT(tokenCreator);
          JsonObject responseObject = new JsonObject().put("token", at);
          endJson(ctx, 201, responseObject.encode());
        } catch (Exception e) {
          endText(ctx, 500, String.format("Unanticipated exception creating access token: %s", e.getMessage()));
        }
      });
    } catch (Exception e) {
      endText(ctx, 500, String.format("Unanticipated exception when handling refresh: %s", e.getMessage()));
    }
  }
}
