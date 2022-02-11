package org.folio.auth.authtokenmodule;

import com.nimbusds.jose.JOSEException;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.impl.DummyPermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.ModuleToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;
import org.folio.okapi.common.XOkapiHeaders;
import org.folio.okapi.common.logging.FolioLoggingContext;

import org.folio.tlib.RouterCreator;
import org.folio.tlib.TenantInitHooks;

import static java.lang.Boolean.TRUE;

/**
 *
 * @author kurt
 */
public class AuthorizeApi implements RouterCreator, TenantInitHooks {

  public static final String SIGN_TOKEN_PERMISSION = "auth.signtoken";
  public static final String SIGN_REFRESH_TOKEN_PERMISSION = "auth.signrefreshtoken";
  private static final String MISSING_HEADER = "Missing header: ";
  private static final String EXTRA_PERMS = "extra_permissions";

  PermissionsSource permissionsSource;
  private static final Logger logger = LogManager.getLogger(AuthorizeApi.class);

  private static final String PERMISSIONS_USER_READ_BIT = "perms.users.get";
  private static final String PERMISSIONS_PERMISSION_READ_BIT = "perms.permissions.get";

  private UserService userService;
  private static final String PERMISSIONS_USERS_ITEM_GET = "users.item.get";

  private PermService permService;

  private TokenCreator tokenCreator;

  private List<AuthRoutingEntry> authRoutingEntryList;

  private Map<String, TokenCreator> clientTokenCreatorMap;

  private static void endText(RoutingContext ctx, int code, String msg) {
    logger.error(msg);
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(MainVerticle.CONTENT_TYPE, "text/plain");
    ctx.response().end(msg);
  }

  private static void endJson(RoutingContext ctx, int code, String msg) {
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON);
    ctx.response().end(msg);
  }

  private static void endText(RoutingContext ctx, int code, String lead, Throwable t) {
    logger.error(lead, t);
    endText(ctx, code, lead + t.getLocalizedMessage());
  }

  private static void endText(RoutingContext ctx, int code, Throwable t) {
    endText(ctx, code, "Error: ", t);
  }

  public AuthorizeApi() {
  }

  public AuthorizeApi(Vertx vertx, TokenCreator tc) {
    authRoutingEntryList = new ArrayList<>();
    authRoutingEntryList.add(new AuthRoutingEntry("/token",
        new String[] { SIGN_TOKEN_PERMISSION }, this::handleSignToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/refreshtoken",
        new String[] { SIGN_REFRESH_TOKEN_PERMISSION }, this::handleSignRefreshToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/refresh",
        new String[] {}, this::handleRefresh));
    authRoutingEntryList.add(new AuthRoutingEntry("/encrypted-token/create",
        new String[] {}, this::handleSignEncryptedToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/encrypted-token/decode",
        new String[] {}, this::handleDecodeEncryptedToken));

    tokenCreator = tc;

    clientTokenCreatorMap = new HashMap<>();

    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    int userCacheInSeconds = Integer.parseInt(System.getProperty("user.cache.seconds", "60")); // 1 minute
    int userCachePurgeInSeconds = Integer.parseInt(System.getProperty("user.cache.purge.seconds", "43200")); // 12 hours
    int sysPermCacheInSeconds = Integer.parseInt(System.getProperty("sys.perm.cache.seconds", "259200")); // 3 days
    int sysPermCachePurgeInSeconds = Integer.parseInt(System.getProperty("sys.perm.cache.purge.seconds", "43200")); // 12
                                                                                                                    // hours

    permissionsSource = new ModulePermissionsSource(vertx, permLookupTimeout);

    userService = new UserService(vertx, userCacheInSeconds, userCachePurgeInSeconds);
    permService = new PermService(vertx, (ModulePermissionsSource) permissionsSource, sysPermCacheInSeconds,
        sysPermCachePurgeInSeconds);
  }

  @Override
  public Future<Router> createRouter(Vertx vertx) {
    Router router = Router.router(vertx);
    router.route("/*").handler(BodyHandler.create());
    router.route("/*").handler(this::handleAuthorize);
    return Future.succeededFuture(router);
  }

  @Override
  public Future<Void> postInit(Vertx vertx, String tenant, JsonObject tenantAttributes) {
    var refreshTokenStore = new RefreshTokenStore(vertx, tenant);
    var apiTokenStore = new ApiTokenStore(vertx, tenant, tokenCreator);
      return refreshTokenStore.createIfNotExists().compose(x -> {
      return apiTokenStore.createIfNotExists();
    });
  }

  private TokenCreator lookupTokenCreator(String passPhrase) throws JOSEException {
    if (clientTokenCreatorMap.containsKey(passPhrase)) {
      return clientTokenCreatorMap.get(passPhrase);
    }
    TokenCreator localTokenCreator = new TokenCreator(passPhrase);
    clientTokenCreatorMap.put(passPhrase, localTokenCreator);
    return localTokenCreator;
  }

  private void handleSignEncryptedToken(RoutingContext ctx) {
    try {
      logger.debug("Encrypted token signing request from {}", ctx.request().absoluteURI());

      JsonObject requestJson = parseEncryptionRequest(ctx, new String[] { "passPhrase", "payload" });
      String passPhrase = requestJson.getString("passPhrase");
      TokenCreator localTokenCreator = lookupTokenCreator(passPhrase);
      String token = localTokenCreator.createJWEToken(requestJson.getJsonObject("payload")
          .encode());

      JsonObject responseJson = new JsonObject().put("token", token);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 400, e);
    }
  }

  /*
   * Decode a provided JSON object into an encrypted token as a service
   * The content of the request should look like:
   * {
   * "passPhrase" : "",
   * "token" : {
   * }
   * }
   */
  private void handleDecodeEncryptedToken(RoutingContext ctx) {
    try {
      JsonObject requestJson = parseEncryptionRequest(ctx, new String[] { "passPhrase", "token" });
      String passPhrase = requestJson.getString("passPhrase");
      TokenCreator localTokenCreator = lookupTokenCreator(passPhrase);
      String token = requestJson.getString("token");
      String encodedJson = localTokenCreator.decodeJWEToken(token);

      JsonObject responseJson = new JsonObject().put("payload", new JsonObject(encodedJson));
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  private JsonObject parseEncryptionRequest(RoutingContext ctx, String[] requiredProperties) {
    if (ctx.request().method() != HttpMethod.POST) {
      String message = "Invalid method for this endpoint";
      endText(ctx, 400, message);
      return null;
    }
    String content = ctx.getBodyAsString();
    JsonObject requestJson = null;
    try {
      requestJson = parseJsonObject(content, requiredProperties);
    } catch (Exception e) {
      String message = String.format("Unable to parse content: %s", e.getLocalizedMessage());
      endText(ctx, 400, message);
      return null;
    }
    return requestJson;
  }

  /*
   * In order to get a new access token, the client should issue a POST request
   * to the refresh endpoint, with the content being a JSON object with the
   * following
   * structure:
   * {
   * "refreshToken" : ""
   * }. The module will then check the refresh token for validity, generate a new
   * access token
   * and return it in the body of the response as a JSON object:
   * {
   * "token" : ""
   * }
   */
  private void handleRefresh(RoutingContext ctx) {
    try {
      logger.debug("Token refresh request from {}", ctx.request().absoluteURI());

      if (ctx.request().method() != HttpMethod.POST) {
        endText(ctx, 400, "Invalid method for this endpoint");
        return;
      }

      String content = ctx.getBodyAsString();
      JsonObject requestJson;

      try {
        requestJson = parseJsonObject(content, new String[] { "refreshToken" });
      } catch (Exception e) {
        endText(ctx, 400, "Unable to parse content of refresh token request: ", e);
        return;
      }

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
          return;
        } catch (Exception e) {
          endText(ctx, 500, String.format("Unanticipated exception creating access token: %s", e.getMessage()));
          return;
        }
      });
    } catch (Exception e) {
      endText(ctx, 500, String.format("Unanticipated exception when handling refresh: %s", e.getMessage()));
    }
  }

  private void handleTokenValidationFailure(Throwable h, RoutingContext ctx,
      String msg, String unexpectedExceptionMsg) {
    if (h instanceof TokenValidationException) {
      var e = (TokenValidationException) h;
      logger.error("{}: {}", msg, e.toString());
      endText(ctx, e.getHttpResponseCode(), msg);
      return;
    }
    logger.error("{}: {}", unexpectedExceptionMsg, h.toString());
    endText(ctx, 500, unexpectedExceptionMsg);
    return;
  }

  /*
   * POST a request with a json payload, containing the following:
   * {
   * "userId" : "",
   * "sub" : ""
   * }
   */
  private void handleSignRefreshToken(RoutingContext ctx) {
    try {
      if (ctx.request().method() != HttpMethod.POST) {
        String message = String.format("Invalid method '%s' for this endpoint '%s'",
            ctx.request().method().toString(),
            ctx.request().absoluteURI());
        endText(ctx, 400, message);
        return;
      }
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      String address = ctx.request().remoteAddress().host();
      String content = ctx.getBodyAsString();
      JsonObject requestJson;
      try {
        requestJson = parseJsonObject(content, new String[] { "userId", "sub" });
      } catch (Exception e) {
        endText(ctx, 400, "Unable to parse content: ", e);
        return;
      }
      String userId = requestJson.getString("userId");
      String sub = requestJson.getString("sub");
      String refreshToken = new RefreshToken(tenant, sub, userId, address).encodeAsJWE(tokenCreator);
      JsonObject responseJson = new JsonObject().put("refreshToken", refreshToken);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  /*
   * Handle a request to sign a new token
   * (Typically used by login module)
   * Request content:
   * {
   * "payload" : { }
   * }
   */
  private void handleSignToken(RoutingContext ctx) {
    try {
      logger.debug("Token signing request from {}", ctx.request().absoluteURI());
      // tenant and okapiUrl are already checked in handleAuthorize
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      if (ctx.request().method() != HttpMethod.POST) {
        endText(ctx, 400, "Unsupported operation: " + ctx.request().method().toString());
        return;
      }
      final String postContent = ctx.getBodyAsString();
      JsonObject json;
      JsonObject payload;
      try {
        json = new JsonObject(postContent);
      } catch (DecodeException dex) {
        endText(ctx, 400, "Unable to decode '" + postContent + "' as valid JSON");
        return;
      }
      payload = json.getJsonObject("payload");

      if (payload == null) {
        endText(ctx, 400, "Valid 'payload' field is required");
        return;
      }
      logger.debug("Payload to create token from is {}", payload.encode());

      if (!payload.containsKey("sub")) {
        endText(ctx, 400, "Payload must contain a 'sub' field");
        return;
      }

      String userId = payload.getString("user_id");
      if (userId != null) {
        permissionsSource.clearCacheUser(userId, tenant);
      }
      String username = payload.getString("sub");
      Token token;
      // auth 2.0 did not expose the "type" property which is now used internally.
      // Only normal (access tokens) are exposed as well as dummy tokens (mod-users-bl).
      if (payload.getBoolean("dummy", Boolean.FALSE)) {
        token = new DummyToken(tenant, payload.getJsonArray("extra_permissions"), username);
      } else {
        token = new AccessToken(tenant, username, userId);
      }
      JsonObject responseObject = new JsonObject().put("token", token.encodeAsJWT(tokenCreator));
      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      endText(ctx, 400, e);
    }
  }

  private void handleAuthorize(RoutingContext ctx) {
    String requestId = ctx.request().headers().get(XOkapiHeaders.REQUEST_ID);
    String userId = ctx.request().headers().get(XOkapiHeaders.USER_ID);
    String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
    FolioLoggingContext.put(FolioLoggingContext.REQUEST_ID_LOGGING_VAR_NAME, requestId);
    FolioLoggingContext.put(FolioLoggingContext.MODULE_ID_LOGGING_VAR_NAME, "mod-authtoken");
    FolioLoggingContext.put(FolioLoggingContext.TENANT_ID_LOGGING_VAR_NAME, tenant);
    FolioLoggingContext.put(FolioLoggingContext.USER_ID_LOGGING_VAR_NAME, userId);
    logger.debug("Calling handleAuthorize for {}", ctx.request().absoluteURI());
    if (tenant == null) {
      endText(ctx, 400, MISSING_HEADER + XOkapiHeaders.TENANT);
      return;
    }

    String okapiUrl = ctx.request().headers().get(XOkapiHeaders.URL);
    if (okapiUrl == null) {
      endText(ctx, 400, MISSING_HEADER + XOkapiHeaders.URL);
      return;
    }
    String zapCacheString = ctx.request().headers().get(MainVerticle.ZAP_CACHE_HEADER);
    boolean zapCache = "true".equals(zapCacheString);

    String authHeader = ctx.request().headers().get("Authorization");
    String okapiTokenHeader = ctx.request().headers().get(XOkapiHeaders.TOKEN);
    String candidateToken;
    if (okapiTokenHeader != null && authHeader != null) {
      String authToken = extractToken(authHeader);
      if (okapiTokenHeader.equals(authToken)) { // authToken may be null
        candidateToken = authToken;
      } else {
        endText(ctx, 400, "Conflicting token information in Authorization and "
            + XOkapiHeaders.TOKEN + " headers. Please remove Authorization header "
            + " and use " + XOkapiHeaders.TOKEN + " in the future");
        return;
      }
    } else if (okapiTokenHeader != null) {
      candidateToken = okapiTokenHeader;
    } else if (authHeader != null) {
      candidateToken = extractToken(authHeader);
    } else {
      candidateToken = null;
    }

    if (candidateToken == null) {
      logger.debug("Generating dummy authtoken");
      try {
        candidateToken = new DummyToken(tenant,
            ctx.request().remoteAddress().toString()).encodeAsJWT(tokenCreator);
      } catch (Exception e) {
        endText(ctx, 500, "Error creating candidate token: ", e);
        return;
      }
    }

    /*
     * In order to make our request to the permissions or users modules
     * we generate a custom token (since we have that power) that
     * has the necessary permissions in it. This prevents an
     * ugly 'lookup loop'.
     */
    String permissionsRequestToken;
    String userRequestToken;
    try {
      var rtPerms = new JsonArray().add(PERMISSIONS_PERMISSION_READ_BIT).add(PERMISSIONS_USER_READ_BIT);
      permissionsRequestToken = new DummyToken(tenant, rtPerms).encodeAsJWT(tokenCreator);
      var userRTPerms = new JsonArray().add(PERMISSIONS_USERS_ITEM_GET);
      userRequestToken = new DummyToken(tenant, userRTPerms).encodeAsJWT(tokenCreator);
    } catch (Exception e) {
      endText(ctx, 500, "Error creating request token: ", e);
      return;
    }

    final String authToken = candidateToken;
    logger.debug("Final authToken is {}", authToken);

    var context = new TokenValidationContext(ctx.request(), tokenCreator, authToken);
    Future<Token> tokenValidationResult = Token.validate(context);

    tokenValidationResult.onFailure(h -> {
      String msg = "Invalid token in handleAuthorize";
      String unexpectedExceptionMsg = "Unexpected token exception in handleAuthorize";
      handleTokenValidationFailure(h, ctx, msg, unexpectedExceptionMsg);
    });

    tokenValidationResult.onSuccess(token -> {
      logger.debug("Validated token of type: {}", token.getClaims().getString("type"));

      String username = token.getClaims().getString("sub");

      // At this point, since we have validated what we can, if there is no userId
      // in the header, we can get the userId from the token.
      final String finalUserId = userId != null ? userId : token.getClaims().getString("user_id");

      // Check and see if we have any module permissions defined.
      JsonArray extraPermissionsCandidate = token.getClaims().getJsonArray(EXTRA_PERMS);
      if (extraPermissionsCandidate == null) {
        extraPermissionsCandidate = new JsonArray();
      }

      // In some rare cases (redirect) Okapi can pass extra permissions directly too
      if (ctx.request().headers().contains(XOkapiHeaders.EXTRA_PERMISSIONS)) {
        String extraPermString = ctx.request().headers().get(XOkapiHeaders.EXTRA_PERMISSIONS);
        logger.debug("Extra permissions from {}: {}", XOkapiHeaders.EXTRA_PERMISSIONS, extraPermString);
        for (String entry : extraPermString.split(",")) {
          extraPermissionsCandidate.add(entry);
        }
      }

      final JsonArray extraPermissions = extraPermissionsCandidate;

      // Instead of storing tokens, let's store an array of objects that each

      JsonObject moduleTokens = new JsonObject();
      /* TODO get module permissions (if they exist) */
      if (ctx.request().headers().contains(XOkapiHeaders.MODULE_PERMISSIONS)) {
        JsonObject modulePermissions = new JsonObject(ctx.request().headers().get(XOkapiHeaders.MODULE_PERMISSIONS));
        for (String moduleName : modulePermissions.fieldNames()) {
          JsonArray permissionList = modulePermissions.getJsonArray(moduleName);
          String moduleToken;
          try {
            moduleToken = new ModuleToken(tenant, username, finalUserId, moduleName, permissionList)
                .encodeAsJWT(tokenCreator);
          } catch (Exception e) {
            String message = String.format("Error creating moduleToken: %s",
                e.getLocalizedMessage());
            logger.error(message);
            endText(ctx, 500, "Error generating module permissions token");
            return;
          }
          moduleTokens.put(moduleName, moduleToken);
        }
      }
      // Add the original token back into the module tokens
      moduleTokens.put("_", authToken);

      /*
       * When the initial request comes in, as a filter, we require that the
       * auth.signtoken
       * permission exists in the module tokens. This means that even if a request has
       * the permission in its permissions list, it cannot request a token unless
       * it has been granted at the module level. If it passes the filter
       * successfully,
       * a new permission, auth.signtoken.execute is attached to the outgoing request
       * which the /token handler will check for when it processes the actual request
       */

      for (AuthRoutingEntry authRoutingEntry : authRoutingEntryList) {
        if (authRoutingEntry.handleRoute(ctx, authToken, moduleTokens.encode())) {
          return;
        }
      }

      // Populate the permissionsRequired array from the header
      JsonArray permissionsRequired = new JsonArray();
      JsonArray permissionsDesired = new JsonArray();

      if (ctx.request().headers().contains(XOkapiHeaders.PERMISSIONS_REQUIRED)) {
        String permissionsString = ctx.request().headers().get(XOkapiHeaders.PERMISSIONS_REQUIRED);
        for (String entry : permissionsString.split(",")) {
          permissionsRequired.add(entry);
        }
      }

      if (ctx.request().headers().contains(XOkapiHeaders.PERMISSIONS_DESIRED)) {
        String permString = ctx.request().headers().get(XOkapiHeaders.PERMISSIONS_DESIRED);
        for (String entry : permString.split(",")) {
          permissionsDesired.add(entry);
        }
      }

      PermissionsSource usePermissionsSource;
      if (token.shouldUseDummyPermissionsSource()) {
        logger.debug("Using dummy permissions source for token type: {}", token.getClaims().getString("type"));
        usePermissionsSource = new DummyPermissionsSource();
      } else {
        usePermissionsSource = permissionsSource;
      }

      if (zapCache) {
        usePermissionsSource.clearCache();
      }

      // Retrieve the user permissions and populate the permissions header
      logger.debug("Getting user permissions for {} (finalUserId {})", username, finalUserId);
      long startTime = System.currentTimeMillis();

      JsonArray expandedSystemPermissions = new JsonArray();

      // Need to check if the user is still active.
      Future<Boolean> activeUser = Future.succeededFuture(Boolean.TRUE);
      if (token.shouldCheckIfUserIsActive(finalUserId)) {
        activeUser = userService.isActiveUser(finalUserId, tenant, okapiUrl, userRequestToken, requestId);
      }
      Future<PermissionData> retrievedPermissionsFuture = activeUser.compose(b -> {
        if (TRUE.equals(b)) {
          return permService.expandSystemPermissions(extraPermissions, tenant, okapiUrl, permissionsRequestToken,
              requestId);
        } else {
          String msg = String.format("Invalid token: user with id {} is not active", finalUserId);
          endText(ctx, 401, msg);
          return Future.failedFuture(msg);
        }
      }).compose(expandedPermissions -> {
        expandedSystemPermissions.addAll(expandedPermissions);
        // Skip expanded system permissions.
        JsonArray extraPermsMinusSystemOnes = new JsonArray();
        extraPermissions.forEach(it -> {
          if (!((String) it).startsWith(PermService.SYS_PERM_PREFIX)) {
            extraPermsMinusSystemOnes.add(it);
          }
        });
        return usePermissionsSource.getUserAndExpandedPermissions(finalUserId, tenant, okapiUrl,
            permissionsRequestToken, requestId, extraPermsMinusSystemOnes);
      });

      logger.debug("Retrieving permissions for userid {} and expanding permissions", finalUserId);
      retrievedPermissionsFuture.onComplete(res -> {
        if (res.failed()) {
          // Vert.x 4 warns about this.. And it's true : response already written 19 lines
          // above
          if (ctx.response().ended()) {
            return;
          }
          long stopTime = System.currentTimeMillis();
          logger.error("Unable to retrieve permissions for {}: {} request took {} ms",
              username, res.cause().getMessage(), stopTime - startTime);
          if (res.cause() instanceof UserService.UserServiceException) {
            endText(ctx, 401, "Invalid token: " + res.cause().getLocalizedMessage());
            return;
          }
          // mod-authtoken should return the module tokens header even in case of errors.
          // If not, pre+post filters will NOT get modulePermissions from Okapi
          ctx.response().putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens.encode());
          String msg = String.format("Unable to retrieve permissions for user with id '%s': %s",
              finalUserId, res.cause().getLocalizedMessage());
          endText(ctx, 400, msg);
          return;
        }

        JsonArray permissions = new JsonArray();
        mergePerms(permissions, res.result().getUserPermissions());
        mergePerms(permissions, res.result().getExpandedPermissions());
        mergePerms(permissions, expandedSystemPermissions);

        // Check that for all required permissions, we have them
        for (Object o : permissionsRequired) {
          if (!permissions.contains(o)
              && !extraPermissions.contains(o)) {
            logger.error(permissions.encode() + "{} (user permissions) nor {}"
                + " (module permissions) do not contain {}",
                permissions.encode(), extraPermissions.encode(), o);
            // mod-authtoken should return the module tokens header even in case of errors.
            // If not, pre+post filters will NOT get modulePermissions from Okapi
            ctx.response().putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens.encode());
            endText(ctx, 403, "Access requires permission: " + o);
            return;
          }
        }

        // Remove all permissions not listed in permissionsRequired or
        // permissionsDesired
        List<Object> deleteList = new ArrayList<>();
        for (Object o : permissions) {
          if (!permissionsRequired.contains(o) && !Util.arrayContainsGlob(permissionsDesired, (String) o)) {
            deleteList.add(o);
          }
        }

        for (Object o : deleteList) {
          permissions.remove(o);
        }

        String finalToken;
        try {
          finalToken = token.encodeAsJWT(tokenCreator);
        } catch (Exception e) {
          String message = String.format("Error creating final token: %s", e.getMessage());
          logger.error(message);
          // mod-authtoken should return the module tokens header even in case of errors.
          // If not, pre+post filters will NOT get modulePermissions from Okapi.
          ctx.response().putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens.encode());
          endText(ctx, 500, "Error creating access token");
          return;
        }

        // Return header containing relevant permissions
        ctx.response()
            .setChunked(true)
            .setStatusCode(202)
            .putHeader(MainVerticle.CONTENT_TYPE, "text/plain")
            .putHeader(XOkapiHeaders.PERMISSIONS, permissions.encode())
            .putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens.encode())
            .putHeader("Authorization", "Bearer " + finalToken)
            .putHeader(XOkapiHeaders.TOKEN, finalToken);

        if (finalUserId != null) {
          ctx.response().putHeader(XOkapiHeaders.USER_ID, finalUserId);
        }

        ctx.response().end();
      });
    });
  }

  private void mergePerms(JsonArray perms, JsonArray morePerms) {
    for (Object o : morePerms) {
      String permName = (String) o;
      if (!perms.contains(permName)) {
        perms.add(permName);
      }
    }
  }

  public String extractToken(String authorizationHeader) {
    // Grab anything after 'Bearer' and whitespace
    Pattern pattern = Pattern.compile("Bearer\\s+(.+)");
    Matcher matcher = pattern.matcher(authorizationHeader);
    if (matcher.find() && matcher.groupCount() > 0) {
      return matcher.group(1);
    }
    return null;
  }

  private JsonObject parseJsonObject(String encoded, String[] requiredMembers)
      throws AuthtokenException {
    JsonObject json;
    try {
      json = new JsonObject(encoded);
    } catch (Exception e) {
      throw new AuthtokenException(String.format("Unable to parse JSON %s: %s", encoded,
          e.getLocalizedMessage()));
    }
    for (String s : requiredMembers) {
      if (!json.containsKey(s)) {
        throw new AuthtokenException(String.format("Missing required member: '%s'", s));
      }
      if (json.getValue(s) == null) {
        throw new AuthtokenException(String.format("Null value for required member: '%s'", s));
      }
    }
    return json;
  }
}
