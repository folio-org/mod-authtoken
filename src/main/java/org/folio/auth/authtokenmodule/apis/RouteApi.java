package org.folio.auth.authtokenmodule.apis;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.openapi.RouterBuilder;

import org.apache.commons.lang3.StringUtils;
import org.folio.auth.authtokenmodule.PermissionsSource;
import org.folio.auth.authtokenmodule.UserService;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.legacy.LegacyTokenTenantException;
import org.folio.auth.authtokenmodule.tokens.legacy.LegacyTokenTenants;
import org.folio.auth.authtokenmodule.tokens.legacy.LegacyAccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;
import org.folio.auth.authtokenmodule.tokens.expiration.TokenExpiration;
import org.folio.okapi.common.XOkapiHeaders;

import java.util.ArrayList;
import java.util.List;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;

import org.apache.logging.log4j.LogManager;

import org.folio.tlib.RouterCreator;
import org.folio.tlib.TenantInitHooks;

/**
 * This API class handles any non-filter routes that this module must serve. The
 * filter API calls
 * these routes.
 *
 * @see FilterApi
 */
public class RouteApi extends Api implements RouterCreator, TenantInitHooks {
  private static final String SIGN_TOKEN_PERMISSION = "auth.signtoken";
  private static final String SIGN_REFRESH_TOKEN_PERMISSION = "auth.signrefreshtoken";
  private static final String USER_ID = "user_id";

  private PermissionsSource permissionsSource;
  private TokenCreator tokenCreator;
  private UserService userService;
  private List<Route> routes;
  private Vertx vertx;
  private TokenExpiration tokenExpiration;
  private LegacyTokenTenants legacyTokenTenants;

  /**
   * Constructs the API.
   *
   * @param vertx        A reference to the current Vertx object.
   * @param tokenCreator A reference to the TokenCreator object. This object is
   *                     shared among all Api classes.
   * @param userService  A reference to the user service which is responsible
   *                     for the validation of the user state
   */
  public RouteApi(Vertx vertx, TokenCreator tokenCreator, UserService userService) {
    this.vertx = vertx;
    this.userService = userService;
    this.tokenCreator = tokenCreator;

    tokenExpiration = new TokenExpiration();
    legacyTokenTenants = new LegacyTokenTenants();
    logger = LogManager.getLogger(RouteApi.class);
    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    permissionsSource = new ModulePermissionsSource(vertx, permLookupTimeout);


    // Set up the routes. Here next will call operation handler defined in
    // createRouter. The filter API is responsible for calling these routes, but we
    // define them here.
    routes = new ArrayList<>();
    routes.add(new Route("/token/sign",
        new String[] { SIGN_TOKEN_PERMISSION }, RoutingContext::next));
    routes.add(new Route("/token/refresh",
        new String[] { SIGN_REFRESH_TOKEN_PERMISSION }, RoutingContext::next));
    routes.add(new Route("/token/invalidate-all",
        new String[] { }, RoutingContext::next));
    // Must come after /invalidate-all because of startsWithMatching in Route.java.
    routes.add(new Route("/token/invalidate",
        new String[] { }, RoutingContext::next));
    routes.add(new Route("/_/tenant",
        new String[] {}, RoutingContext::next));
    // The "legacy" routes.
    routes.add(new Route("/refreshtoken",
        new String[] { SIGN_REFRESH_TOKEN_PERMISSION }, RoutingContext::next));
    // This must be last because of the startsWith matching in Route.java.
    routes.add(new Route("/token",
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
              .operation("token-sign-legacy")
              .handler(this::handleSignRefreshTokenLegacy);
          routerBuilder
              .operation("token-refresh")
              .handler(this::handleRefresh);
          routerBuilder
              .operation("token-sign")
              .handler(this::handleSignToken);
           routerBuilder
              .operation("token-invalidate")
              .handler(this::handleTokenLogout);
           routerBuilder
              .operation("token-invalidate-all")
              .handler(this::handleTokenLogoutAll);
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
   * Given the current request, attempt to handle the request as a route with an
   * endpoint specified in this class. If the route has been found this method will
   * return true.
   *
   * @param ctx          The current http context.
   * @param authToken    The auth token in scope for this request.
   * @param moduleTokens An encoded JSON object of module tokens.
   * @param expandedPermissions expanded permissions from token or header.
   */
  public boolean tryHandleRoute(RoutingContext ctx, String authToken, String moduleTokens,
    JsonArray expandedPermissions) {
    for (Route route : routes) {
      if (route.handleRoute(ctx, authToken, moduleTokens, expandedPermissions)) {
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
   * When the request is an AccessToken singing request it will have a user_id
   * property.
   *
   * The only property that is required and which both of these requests have in
   * common is the sub property.
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

      // Both types of signing requests (dummy and access) have only this property in
      // common.
      String username = payload.getString("sub");
      String userId = payload.getString(USER_ID);

      var responseObject = new JsonObject();

      // auth 2.0 did not expose the "type" property which is now used internally. But
      // other modules like mod-login aren't aware of this type property. Because of this
      // dummy token singing requests have a boolean which can be checked to distinguish
      // regular access token signing requests.
      if (isDummyTokenSigningRequest(payload)) {
        logger.debug("Signing request is for a dummy token");

        var dt = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
        responseObject.put("token", dt.encodeAsJWT(tokenCreator));
        endJson(ctx, 201, responseObject.encode());

        return;
      }
      logger.debug("Signing request is for an access token");

      // Clear the user from the permissions cache.
      permissionsSource.clearCacheUser(userId, tenant);

      returnTokens(ctx, tenant, username, userId, responseObject);

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
      JsonObject requestJson = ctx.body().asJsonObject();
      String encryptedJWE = requestJson.getString(Token.REFRESH_TOKEN);
      Token parsedToken = Token.parse(encryptedJWE, tokenCreator);
      String tenant = StringUtils.defaultIfBlank(parsedToken.getTenant(), ctx.request().headers().get(XOkapiHeaders.TENANT));
      var refreshTokenStore = new RefreshTokenStore(vertx, tenant);

      var context = new TokenValidationContext(ctx.request(), tokenCreator, encryptedJWE, refreshTokenStore, userService);
      Future<Token> tokenValidationResult = Token.validate(parsedToken, context);

      tokenValidationResult.onFailure(e -> handleTokenValidationFailure(e, ctx));

      tokenValidationResult.onSuccess(token -> {
        String username = token.getClaim("sub");
        String userId = token.getClaim(USER_ID);

        JsonObject responseObject = new JsonObject();

        returnTokens(ctx, tenant, username, userId, responseObject);
      });
    } catch (TokenValidationException e) {
      handleTokenValidationFailure(e, ctx);
    } catch (Exception e) {
      endText(ctx, 500, "Cannot handle refresh: " + e.getMessage());
    }
  }

  private void returnTokens(
      RoutingContext ctx,
      String tenant,
      String username,
      String userId,
      JsonObject responseObject) {

    String address = ctx.request().remoteAddress().host();
    var rt = new RefreshToken(tenant, username, userId, address, tokenExpiration.getRefreshTokenExpiration(tenant));
    var at = new AccessToken(tenant, username, userId, tokenExpiration.getAccessTokenExpiration(tenant));

    try {
      responseObject.put(Token.ACCESS_TOKEN, at.encodeAsJWT(tokenCreator));
      responseObject.put(Token.REFRESH_TOKEN, rt.encodeAsJWE(tokenCreator));
      responseObject.put(Token.ACCESS_TOKEN_EXPIRATION, at.getExpiresAtInIso8601Format());
      responseObject.put(Token.REFRESH_TOKEN_EXPIRATION, rt.getExpiresAtInIso8601Format());
    } catch (JOSEException e) {
      endText(ctx, 500, "Unable to encode token", e);
    } catch (ParseException e) {
      endText(ctx, 500, "Parse exception", e);
    }

    // Save the RT to track one-time use.
    new RefreshTokenStore(vertx, tenant).saveToken(rt)
        .onSuccess(x -> endJson(ctx, 201, responseObject.encode()))
        .onFailure(e -> handleTokenValidationFailure(e, ctx));
  }

  private void handleTokenLogout(RoutingContext ctx) {
    try {
      logger.debug("Called handleTokenLogout");
      JsonObject requestJson = ctx.body().asJsonObject();
      String encryptedJWE = requestJson.getString(Token.REFRESH_TOKEN);
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);

      RefreshToken rt = (RefreshToken)Token.parse(encryptedJWE, tokenCreator);

      var refreshTokenStore = new RefreshTokenStore(vertx, tenant);
      refreshTokenStore.revokeToken(rt)
          .onSuccess(x -> endNoContent(ctx, 204))
          .onFailure(e -> handleTokenValidationFailure(e, ctx));
    } catch (Exception e) {
      endText(ctx, 500, "Cannot handle token logout:" + e.getMessage());
    }
  }

  private void handleTokenLogoutAll(RoutingContext ctx) {
    try {
      logger.debug("Called handleTokenLogoutAll");

      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      String accessTokenString = ctx.request().headers().get(XOkapiHeaders.TOKEN);

      AccessToken at = (AccessToken)Token.parse(accessTokenString, tokenCreator);

      var refreshTokenStore = new RefreshTokenStore(vertx, tenant);
      refreshTokenStore.revokeAllTokensForUser(at.getUserId())
          .onSuccess(x -> endNoContent(ctx, 204))
          .onFailure(e -> handleTokenValidationFailure(e, ctx));
    } catch (Exception e) {
      endText(ctx, 500, "Cannot handle token logout all: " + e.getMessage());
    }
  }

  // Legacy methods. These next two methods can be removed once we stop supporting
  // legacy tokens.

  private void handleSignLegacyToken(RoutingContext ctx) {
    try {
      // X-Okapi-Tenant and X-Okapi-Url are already checked in FilterApi.
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);

      // Check for enhanced security mode being enabled for the tenant. If so return 404.
      if (!legacyTokenTenants.isLegacyTokenTenant(tenant)) {
        var message = "Tenant not a legacy token tenant as specified in this modules environment or system " +
          "property. Cannot issue non-expiring legacy token.";
       endText(ctx, 404, new LegacyTokenTenantException(message));
      }

      JsonObject json = ctx.body().asJsonObject();
      JsonObject payload;
      payload = json.getJsonObject("payload");

      // Both types of signing requests (dummy and access) have only this property in
      // common.
      String username = payload.getString("sub");
      Token token;

      // auth 2.0 did not expose the "type" property which is now used internally. But
      // other modules like mod-login aren't aware of this type property. Because of this
      // dummy token singing requests have a boolean which can be checked to distinguish them from
      // regular access token signing requests.
      if (isDummyTokenSigningRequest(payload)) {
        logger.debug("Signing request is for a dummy token");

        token = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
      } else {
        logger.debug("Signing request is for an access token");

        String userId = payload.getString(USER_ID);
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

  private void handleSignRefreshTokenLegacy(RoutingContext ctx) {
    try {
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      String address = ctx.request().remoteAddress().host();
      JsonObject requestJson = ctx.body().asJsonObject();
      String userId = requestJson.getString(USER_ID);
      String sub = requestJson.getString("sub");
      long expires = tokenExpiration.getRefreshTokenExpiration(tenant);
      String refreshToken = new RefreshToken(tenant, sub, userId, address, expires).encodeAsJWE(tokenCreator);
      JsonObject responseJson = new JsonObject().put(Token.REFRESH_TOKEN, refreshToken);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }
}
