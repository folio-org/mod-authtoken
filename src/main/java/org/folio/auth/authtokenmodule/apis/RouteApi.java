package org.folio.auth.authtokenmodule.apis;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.openapi.RouterBuilder;
import io.vertx.core.http.HttpMethod;

import org.folio.auth.authtokenmodule.PermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.okapi.common.XOkapiHeaders;

import java.util.ArrayList;
import java.util.List;

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
    routes.add( new Route("/token",
      new String[] { SIGN_TOKEN_PERMISSION }, RoutingContext::next));
    routes.add(new Route("/refreshtoken",
      new String[] { SIGN_REFRESH_TOKEN_PERMISSION }, RoutingContext::next));
    routes.add(new Route("/refresh",
      new String[] {}, RoutingContext::next));
    routes.add(new Route("/_/tenant",
      new String[] {}, RoutingContext::next));
  }

  @Override
  public Future<Router> createRouter(Vertx vertx) {
    // Bind the openapi yaml definition with the handler methods defined here.
    return RouterBuilder.create(vertx, "openapi/token-1.0.yaml")
        .map(routerBuilder -> {
          routerBuilder
              .operation("refresh")
              .handler(this::handleRefresh);
          routerBuilder
              .operation("refreshtoken")
              .handler(this::handleSignRefreshToken);
          routerBuilder
              .operation("token")
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
   * Given the current request, attempt to handle the request as a route with an endpoint. If
   * the route has been handled (meaning its method in this class has been called) this method
   * will return true.
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

  private void handleSignToken(RoutingContext ctx) {
    try {
      logger.debug("Token signing request from {}", ctx.request().absoluteURI());

      // Tenant and okapiUrl are already checked in AuthorizeApi
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      final String content = ctx.getBodyAsString();
      JsonObject json;
      JsonObject payload;
      json = new JsonObject(content);
      payload = json.getJsonObject("payload");

      logger.debug("Payload to create signed token from is {}", payload.encode());

      String userId = payload.getString("user_id");
      if (userId != null) {
        permissionsSource.clearCacheUser(userId, tenant);
      }
      String username = payload.getString("sub");
      Token token;

      // auth 2.0 did not expose the "type" property which is now used internally.
      // Only normal (access tokens) are exposed as well as dummy tokens
      // (mod-users-bl).
      if (payload.getBoolean("dummy", Boolean.FALSE)) {
        token = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
      } else {
        token = new AccessToken(tenant, username, userId);
      }

      logger.debug("Successfully created and signed token");

      JsonObject responseObject = new JsonObject().put("token", token.encodeAsJWT(tokenCreator));
      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  private void handleRefresh(RoutingContext ctx) {
    try {
      logger.debug("Token refresh request from {}", ctx.request().absoluteURI());

      String content = ctx.getBodyAsString();
      JsonObject requestJson = new JsonObject(content);
      String encryptedJWE = requestJson.getString("refreshToken");
      var context = new TokenValidationContext(ctx.request(), tokenCreator, encryptedJWE);
      Future<Token> tokenValidationResult = Token.validate(context);

      tokenValidationResult.onFailure(h -> {
        String msg = "Invalid token in handleRefresh";
        String unexpectedExceptionMsg = "Unexpected token exception in handleRefresh";
        handleTokenValidationFailure(h, ctx, msg, unexpectedExceptionMsg);
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

  private void handleSignRefreshToken(RoutingContext ctx) {
    try {
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      String address = ctx.request().remoteAddress().host();
      String content = ctx.getBodyAsString();
      JsonObject requestJson =  new JsonObject(content);
      String userId = requestJson.getString("userId");
      String sub = requestJson.getString("sub");
      String refreshToken = new RefreshToken(tenant, sub, userId, address).encodeAsJWE(tokenCreator);
      JsonObject responseJson = new JsonObject().put("refreshToken", refreshToken);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }
}