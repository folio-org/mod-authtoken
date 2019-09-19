package org.folio.auth.authtokenmodule;

import com.nimbusds.jose.JOSEException;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.folio.auth.authtokenmodule.impl.DummyPermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;

/**
 *
 * @author kurt
 */
public class MainVerticle extends AbstractVerticle {

  // TODO - Use header names from Okapi.common
  public static final String PERMISSIONS_HEADER = "X-Okapi-Permissions";
  private static final String CONTENT_TYPE = "Content-Type";
  private static final String DESIRED_PERMISSIONS_HEADER = "X-Okapi-Permissions-Desired";
  private static final String REQUIRED_PERMISSIONS_HEADER = "X-Okapi-Permissions-Required";
  private static final String MODULE_PERMISSIONS_HEADER = "X-Okapi-Module-Permissions";
  private static final String EXTRA_PERMISSIONS_HEADER = "X-Okapi-Extra-Permissions";
  private static final String CALLING_MODULE_HEADER = "X-Okapi-Calling-Module";
  private static final String USERID_HEADER = "X-Okapi-User-Id";
  private static final String REQUESTID_HEADER = "X-Okapi-Request-Id";
  public static final String MODULE_TOKENS_HEADER = "X-Okapi-Module-Tokens";
  private static final String OKAPI_URL_HEADER = "X-Okapi-Url";
  public static final String OKAPI_TOKEN_HEADER = "X-Okapi-Token";
  private static final String OKAPI_TENANT_HEADER = "X-Okapi-Tenant";
  public static final String SIGN_TOKEN_PERMISSION = "auth.signtoken";
  public static final String SIGN_REFRESH_TOKEN_PERMISSION = "auth.signrefreshtoken";
  private static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";
  private static final String TOKEN_USER_ID_FIELD = "user_id";
  private static final String ZAP_CACHE_HEADER = "Authtoken-Refresh-Cache";
  private static final String CACHE_KEY_FIELD = "cache_key";
  private static final String MISSING_HEADER = "Missing header: ";
  private static final int MAX_CACHED_TOKENS = 100; //Probably could be a LOT bigger

  PermissionsSource permissionsSource;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private static final String PERMISSIONS_USER_READ_BIT = "perms.users.get";
  private static final String PERMISSIONS_PERMISSION_READ_BIT = "perms.permissions.get";
  private boolean suppressErrorResponse = false;
  private boolean cachePermissions = true;

  private TokenCreator tokenCreator;

  private LimitedSizeQueue<String> tokenCache;

  private Map<String, String> permissionsRequestTokenMap;
  private List<AuthRoutingEntry> authRoutingEntryList;

  private Map<String, TokenCreator> clientTokenCreatorMap;


  private String logAndReturnError(Throwable t) {
    String message = String.format("Error: %s", t.getLocalizedMessage());
    logger.error(message, t);
    return message;
  }

  TokenCreator getTokenCreator() throws JOSEException {
    String keySetting = System.getProperty("jwt.signing.key");
    return new TokenCreator(keySetting);
  }

  private static void endText(RoutingContext ctx, int code, String msg) {
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(CONTENT_TYPE, "text/plain");
    ctx.response().end(msg);
  }

  private static void endJson(RoutingContext ctx, int code, String msg) {
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(CONTENT_TYPE, "application/json");
    ctx.response().end(msg);
  }

  @Override
  public void start(Future<Void> future) {
    authRoutingEntryList = new ArrayList<>();
    authRoutingEntryList.add(new AuthRoutingEntry("/token",
        new String[] {SIGN_TOKEN_PERMISSION}, this::handleSignToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/refreshtoken",
        new String[] {SIGN_REFRESH_TOKEN_PERMISSION}, this::handleSignRefreshToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/refresh",
        new String[] {}, this::handleRefresh));
    authRoutingEntryList.add(new AuthRoutingEntry("/encrypted-token/create",
        new String[] {}, this::handleSignEncryptedToken));
    authRoutingEntryList.add(new AuthRoutingEntry("/encrypted-token/decode",
        new String[] {}, this::handleDecodeEncryptedToken));
    Router router = Router.router(vertx);
    HttpServer server = vertx.createHttpServer();
    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));

    try {
      tokenCreator = getTokenCreator();
      tokenCreator.dryRunAlgorithms();
    } catch(Exception e) {
      future.fail(new RuntimeException("Unable to initialize TokenCreator: " + e.getLocalizedMessage(), e));
      return;
    }

    String suppressString = System.getProperty("suppress.error.response", "false");
    suppressErrorResponse = suppressString.equals("true");

    String cachePermsString = System.getProperty("cache.permissions", "true");
    cachePermissions = cachePermsString.equals("true");

    permissionsRequestTokenMap = new HashMap<>();
    clientTokenCreatorMap = new HashMap<>();

    tokenCache = new LimitedSizeQueue<>(MAX_CACHED_TOKENS);
    String logLevel = System.getProperty("log.level", null);
    if(logLevel != null) {
      try {
        org.apache.log4j.Logger l4jLogger;
        l4jLogger = org.apache.log4j.Logger.getLogger("mod-auth-authtoken-module");
        l4jLogger.getParent().setLevel(org.apache.log4j.Level.toLevel(logLevel));
      } catch(Exception e) {
        logger.error("Unable to set log level: " + e.getMessage());
      }
    }
    permissionsSource = new ModulePermissionsSource(vertx, permLookupTimeout, cachePermissions);

    // Get the port from context too, the unit test needs to set it there.
    final String defaultPort = context.config().getString("port", "8081");
    final String portStr = System.getProperty("port", defaultPort);
    final int port = Integer.parseInt(portStr);

    router.route("/*").handler(BodyHandler.create());
    router.route("/*").handler(this::handleAuthorize);

    server.requestHandler(router::accept).listen(port, result -> {
        if(result.succeeded()) {
          future.complete();
        } else {
          future.fail(result.cause());
        }
    });


  }

 /*
  Sign a provided JSON object into an encrypted token as a service
  The content of the request should look like:
  {
      "passPhrase" : "",
      "payload" : {
      }
  }
  */
  private void handleSignEncryptedToken(RoutingContext ctx) {
    try {
      TokenCreator localTokenCreator = null;
      logger.debug("Encrypted token signing request from " + ctx.request().absoluteURI());
      if (ctx.request().method() != HttpMethod.POST) {
        String message = "Invalid method for this endpoint";
        endText(ctx, 400, message);
        return;
      }
      String content = ctx.getBodyAsString();
      JsonObject requestJson = null;
      try {
        requestJson = parseJsonObject(content,
          new String[]{"passPhrase", "payload"});
      } catch (Exception e) {
        String message = String.format("Unable to parse content: %s",
          e.getLocalizedMessage());
        endText(ctx, 400, message);
        return;
      }
      String passPhrase = requestJson.getString("passPhrase");
      if (clientTokenCreatorMap.containsKey(passPhrase)) {
        localTokenCreator = clientTokenCreatorMap.get(passPhrase);
      } else {
        localTokenCreator = new TokenCreator(passPhrase);
        clientTokenCreatorMap.put(passPhrase, localTokenCreator);
      }
      String token = localTokenCreator.createJWEToken(requestJson.getJsonObject("payload")
        .encode());
      JsonObject responseJson = new JsonObject()
        .put("token", token);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      String error = logAndReturnError(e);
      endText(ctx, 500, error);
    }
  }

  /*
  Decode a provided JSON object into an encrypted token as a service
  The content of the request should look like:
  {
      "passPhrase" : "",
      "token" : {
      }
  }
  */
  private void handleDecodeEncryptedToken(RoutingContext ctx) {
    try {
      TokenCreator localTokenCreator = null;
      if(ctx.request().method() != HttpMethod.POST) {
        String message = "Invalid method for this endpoint";
        endText(ctx, 400, message);
        return;
      }
      String content = ctx.getBodyAsString();
      JsonObject requestJson = null;
      try {
        requestJson = parseJsonObject(content,
          new String[]{"passPhrase", "token"});
      } catch (Exception e) {
        String message = String.format("Unable to parse content: %s",
          e.getLocalizedMessage());
        endText(ctx, 400, message);
        return;
      }
      String passPhrase = requestJson.getString("passPhrase");
      if (clientTokenCreatorMap.containsKey(passPhrase)) {
        localTokenCreator = clientTokenCreatorMap.get(passPhrase);
      } else {
        localTokenCreator = new TokenCreator(passPhrase);
        clientTokenCreatorMap.put(passPhrase, localTokenCreator);
      }
      String token = requestJson.getString("token");
      String encodedJson = localTokenCreator.decodeJWEToken(token);
      JsonObject responseJson = new JsonObject()
        .put("payload", new JsonObject(encodedJson));
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      String error = logAndReturnError(e);
      endText(ctx, 500, error);
    }
  }

   /*
  In order to get a new access token, the client should issue a POST request
  to the refresh endpoint, with the content being a JSON object with the following
  structure:
  {
    "refreshToken" : ""
  }. The module will then check the refresh token for validity, generate a new access token
  and return it in the body of the response as a JSON object:
  {
    "token" : ""
  }
  */
  private void handleRefresh(RoutingContext ctx) {
    try {
      logger.debug("Token refresh request from " + ctx.request().absoluteURI());
      if (ctx.request().method() != HttpMethod.POST) {
        String message = "Invalid method for this endpoint";
        endText(ctx, 400, message);
        return;
      }
      String content = ctx.getBodyAsString();
      JsonObject requestJson = null;
      try {
        requestJson = parseJsonObject(content,
          new String[]{"refreshToken"});
      } catch (Exception e) {
        String message = String.format("Unable to parse content: %s",
          e.getLocalizedMessage());
        logger.error(message);
        endText(ctx, 400, message);
        return;
      }
      String token = requestJson.getString("refreshToken");
      String tokenContent = null;
      JsonObject tokenClaims = null;
      try {
        tokenContent = tokenCreator.decodeJWEToken(token);
        tokenClaims = new JsonObject(tokenContent);
      } catch (Exception e) {
        String message = String.format("Unable to decode token %s: %s",
          token, e.getLocalizedMessage());
        logger.error(message);
        endText(ctx, 400, "Invalid token format");
        return;
      }
      String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
      //Go ahead and make the new request token
      String newAuthToken = mintNewAuthToken(tenant, tokenClaims);
      validateRefreshToken(tokenClaims, ctx).setHandler(res -> {
        if (res.failed()) {
          String message = logAndReturnError(res.cause());
          endText(ctx, 500, message);
          return;
        }
        if (!res.result()) {
          endText(ctx, 401, "Invalid refresh token");
          return;
        }
        JsonObject responseObject = new JsonObject()
          .put("token", newAuthToken);
        endJson(ctx, 201, responseObject.encode());
      });
    } catch (Exception e) {
      String message = logAndReturnError(e);
      endText(ctx, 500, message);
    }
  }

  /*
  POST a request with a json payload, containing the following:
  {
    "userId" : "",
    "sub" : ""
  }
  */
  private void handleSignRefreshToken(RoutingContext ctx) {
    try {
      if (ctx.request().method() != HttpMethod.POST) {
        String message = String.format("Invalid method '%s' for this endpoint '%s'",
          ctx.request().method().toString(),
          ctx.request().absoluteURI());
        logger.error(message);
        endText(ctx, 400, message);
        return;
      }
      String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
      String address = ctx.request().remoteAddress().host();
      String content = ctx.getBodyAsString();
      JsonObject requestJson = null;
      try {
        requestJson = parseJsonObject(content,
          new String[]{"userId", "sub"});
      } catch (Exception e) {
        String message = String.format("Unable to parse content: %s",
          e.getLocalizedMessage());
        logger.error(message);
        endText(ctx, 400, message);
        return;
      }
      String userId = requestJson.getString("userId");
      String sub = requestJson.getString("sub");
      String refreshToken = generateRefreshToken(tenant, userId, address, sub);
      JsonObject responseJson = new JsonObject()
        .put("refreshToken", refreshToken);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      String error = logAndReturnError(e);
      endText(ctx, 500, error);
    }
  }
  
  /*
   * Handle a request to sign a new token
   * (Typically used by login module)
   Request content:
  {
    "payload" : { }
  }
   */
  private void handleSignToken(RoutingContext ctx) {
    try {
      logger.debug("Token signing request from " +  ctx.request().absoluteURI());
      // tenant and okapiUrl are already checked in handleAuthorize
      String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
      String okapiUrl = ctx.request().headers().get(OKAPI_URL_HEADER);
      if (ctx.request().method() != HttpMethod.POST) {
        endText(ctx, 400, "Unsupported operation: " + ctx.request().method().toString());
        return;
      }
      final String postContent = ctx.getBodyAsString();
      JsonObject json = null;
      JsonObject payload = null;
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
      logger.debug("Payload to create token from is " + payload.encode());

      if (!payload.containsKey("sub")) {
        endText(ctx, 400, "Payload must contain a 'sub' field");
        return;
      }

      payload.put("tenant", tenant);

      if (!payload.containsKey(CACHE_KEY_FIELD)) {
        payload.put(CACHE_KEY_FIELD, UUID.randomUUID().toString());
      }

      //Set "time issued" claim on token
      Instant instant = Instant.now();
      payload.put("iat", instant.getEpochSecond());
      String token = tokenCreator.createJWTToken(payload.encode());

      JsonObject responseObject = new JsonObject().put("token", token);
      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      String message = e.getLocalizedMessage();
      logger.error(message, e);
      endText(ctx, 400, message);
    }
  }

  private void handleAuthorize(RoutingContext ctx) {
    logger.debug("Calling handleAuthorize for " + ctx.request().absoluteURI());
    String requestId = ctx.request().headers().get(REQUESTID_HEADER);
    String userId = ctx.request().headers().get(USERID_HEADER);
    String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
    if (tenant == null) {
      endText(ctx, 400, MISSING_HEADER + OKAPI_TENANT_HEADER);
      return;
    }
    String okapiUrl = ctx.request().headers().get(OKAPI_URL_HEADER);
    if (okapiUrl == null) {
      endText(ctx, 400, MISSING_HEADER + OKAPI_URL_HEADER);
      return;
    }
    String zapCacheString = ctx.request().headers().get(ZAP_CACHE_HEADER);
    boolean zapCache = false;
    if(zapCacheString != null && zapCacheString.equals("true")) {
      zapCache = true;
    }

    //String requestToken = getRequestToken(ctx);
    String authHeader = ctx.request().headers().get("Authorization");
    String okapiTokenHeader = ctx.request().headers().get(OKAPI_TOKEN_HEADER);
    String candidateToken = null;
    if(okapiTokenHeader != null && authHeader != null) {
      String authToken = extractToken(authHeader);
      if(okapiTokenHeader.equals(authToken)) { // authToken may be null
        candidateToken = authToken;
      } else {
        logger.error("Conflict between different auth headers");
        endText(ctx, 400, "Conflicting token information in Authorization and " +
                OKAPI_TOKEN_HEADER + " headers. Please remove Authorization header " +
                " and use " + OKAPI_TOKEN_HEADER + " in the future");
        return;
      }
    } else if(okapiTokenHeader != null) {
      candidateToken = okapiTokenHeader;
    } else if(authHeader != null) {
      candidateToken = extractToken(authHeader);
    } else {
      candidateToken = null;
    }

    /*
      In order to make our request to the permissions module
      we generate a custom token (since we have that power) that
      has the necessary permissions in it. This prevents an
      ugly 'lookup loop'
    */
    String permissionsRequestToken;
    if (permissionsRequestTokenMap.containsKey(tenant)) {
      permissionsRequestToken = permissionsRequestTokenMap.get(tenant);
    } else {
      JsonObject permissionRequestPayload = new JsonObject()
              .put("sub", "_AUTHZ_MODULE_")
              .put("tenant", tenant)
              .put("dummy", true)
              .put("request_id", "PERMISSIONS_REQUEST_TOKEN")
              .put("extra_permissions", new JsonArray()
                      .add(PERMISSIONS_PERMISSION_READ_BIT)
                      .add(PERMISSIONS_USER_READ_BIT));

      try {
        permissionsRequestToken = tokenCreator.createJWTToken(permissionRequestPayload.encode());
      } catch(Exception e) {
        String errStr = "Error creating permission request token: " + e.getMessage();
        logger.error(errStr);
        endText(ctx, 500, errStr);
        return;
      }
    }

    if (candidateToken == null) {
      logger.info("Generating dummy authtoken");
      JsonObject dummyPayload = new JsonObject();
      try {
        //Generate a new "dummy" token
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        Date now = Calendar.getInstance().getTime();
        dummyPayload
                .put("sub", UNDEFINED_USER_NAME + ctx.request().remoteAddress().toString() +
                        "__" + df.format(now))
                .put("tenant", tenant)
                .put("request_id", requestId)
                .put("dummy", true);
      } catch(Exception e) {
        String errStr = "Error creating dummy token: " + e.getMessage();
        logger.error(errStr);
        endText(ctx, 500, errStr);
        return;
      }
      try {
        candidateToken = tokenCreator.createJWTToken(dummyPayload.encode());
      } catch(Exception e) {
        String errStr = "Error creating candidate token: " + e.getMessage();
        logger.error(errStr);
        endText(ctx, 500, errStr);
        return;
      }
    }
 
    final String authToken = candidateToken;
    logger.debug("Final authToken is " + authToken);
    final String errMsg = "Invalid token";
    try {
      if (!tokenCache.contains(authToken)) {
        tokenCreator.checkJWTToken(authToken);
        tokenCache.add(authToken);
      }
    } catch (ParseException p) {
      logger.error("Malformed token: " + authToken, p);
      endText(ctx, 401, errMsg);
      return;
    } catch (JOSEException j) {
      logger.error(String.format("Unable to verify token token %s, %s",
        authToken, j.getLocalizedMessage()));
      endText(ctx, 401, errMsg);
      return;
    } catch (BadSignatureException b) {
      logger.error("Unsupported JWT format", b);
      endText(ctx, 401, errMsg);
      return;
    }

    JsonObject tokenClaims = getClaims(authToken);

    String username = tokenClaims.getString("sub");
    String jwtTenant = tokenClaims.getString("tenant");
    String cacheKey = getClaims(candidateToken).getString(CACHE_KEY_FIELD);

    
    if (jwtTenant == null || !jwtTenant.equals(tenant)) {
      logger.error("Expected tenant: " + tenant + ", got tenant: " + jwtTenant);
      endText(ctx, 403, "Invalid token for access");
      return;
    }

    String tokenUserId = tokenClaims.getString(TOKEN_USER_ID_FIELD);
    if(tokenUserId != null) {
      if (userId != null) {
        if (!userId.equals(tokenUserId)) {
          endText(ctx, 403, 
           "Payload user id of '" + tokenUserId + " does not match expected value.");
          return;
        }
      } else {
        //Assign the userId to be whatever's in the token
        userId = tokenUserId;
      }
    } else {
      logger.debug("No '" + TOKEN_USER_ID_FIELD + "' field found in token");
    }

    final String finalUserId = userId;

    //Check and see if we have any module permissions defined
    JsonArray extraPermissionsCandidate = getClaims(authToken).getJsonArray("extra_permissions");
    if(extraPermissionsCandidate == null) {
      extraPermissionsCandidate = new JsonArray();
    }

    // In some rare cases (redirect) Okapi can pass extra permissions directly too
    if (ctx.request().headers().contains(EXTRA_PERMISSIONS_HEADER)) {
      String extraPermString = ctx.request().headers().get(EXTRA_PERMISSIONS_HEADER);
      logger.debug("Extra permissions from " + EXTRA_PERMISSIONS_HEADER
        + " :" + extraPermString);
      for (String entry : extraPermString.split(",")) {
        extraPermissionsCandidate.add(entry);
      }
    }

    final JsonArray extraPermissions = extraPermissionsCandidate;

    //Instead of storing tokens, let's store an array of objects that each

    JsonObject moduleTokens = new JsonObject();
    /* TODO get module permissions (if they exist) */
    if (ctx.request().headers().contains(MODULE_PERMISSIONS_HEADER)) {
      JsonObject modulePermissions = new JsonObject(ctx.request().headers().get(MODULE_PERMISSIONS_HEADER));
      for(String moduleName : modulePermissions.fieldNames()) {
        JsonArray permissionList = modulePermissions.getJsonArray(moduleName);
        JsonObject tokenPayload = new JsonObject();
        tokenPayload.put("sub", username);
        tokenPayload.put("tenant", tenant);
        tokenPayload.put("module", moduleName);
        tokenPayload.put("extra_permissions", permissionList);
        tokenPayload.put("request_id", requestId);
        tokenPayload.put("user_id", finalUserId);
        tokenPayload.put(CACHE_KEY_FIELD, cacheKey);
        String moduleToken = null;
        try {
          moduleToken = tokenCreator.createJWTToken(tokenPayload.encode());
        } catch(Exception e) {
          String message = String.format("Error creating moduleToken: %s",
              e.getLocalizedMessage());
          logger.error(message);
          endText(ctx, 500, "Error generating module permissions token");
          return;
        }
        moduleTokens.put(moduleName, moduleToken);
     }
    }

    //Add the original token back into the module tokens
    moduleTokens.put("_", authToken);

    /*
    When the initial request comes in, as a filter, we require that the auth.signtoken
    permission exists in the module tokens. This means that even if a request has
    the permission in its permissions list, it cannot request a token unless
    it has been granted at the module level. If it passes the filter successfully,
    a new permission, auth.signtoken.execute is attached to the outgoing request
    which the /token handler will check for when it processes the actual request
    */

    for(AuthRoutingEntry authRoutingEntry : authRoutingEntryList) {
      if(authRoutingEntry.handleRoute(ctx, authToken, moduleTokens.encode())) {
        return;
      }
    }

    //Populate the permissionsRequired array from the header
    JsonArray permissionsRequired = new JsonArray();
    JsonArray permissionsDesired = new JsonArray();

    if(ctx.request().headers().contains(REQUIRED_PERMISSIONS_HEADER)) {
      String permissionsString = ctx.request().headers().get(REQUIRED_PERMISSIONS_HEADER);
      for(String entry : permissionsString.split(",")) {
        permissionsRequired.add(entry);
      }
    }

    if(ctx.request().headers().contains(DESIRED_PERMISSIONS_HEADER)) {
      String permString = ctx.request().headers().get(DESIRED_PERMISSIONS_HEADER);
      for(String entry : permString.split(",")) {
        permissionsDesired.add(entry);
      }
    }

    PermissionsSource usePermissionsSource;
    if((tokenClaims.getBoolean("dummy") != null && tokenClaims.getBoolean("dummy"))
            || username.startsWith(UNDEFINED_USER_NAME)) {
      logger.debug("Using dummy permissions source");
      usePermissionsSource = new DummyPermissionsSource();
    } else {
      usePermissionsSource = permissionsSource;
    }

    if(zapCache && usePermissionsSource instanceof Cache) {
      logger.info("Requesting cleared cache for authToken '" + authToken + "'");
      ((Cache)usePermissionsSource).clearCache(cacheKey);
    }

    //Retrieve the user permissions and populate the permissions header
    logger.debug("Getting user permissions for " + username + " (userId " +
            userId + ")");
    long startTime = System.currentTimeMillis();
    Future<PermissionData> retrievedPermissionsFuture = usePermissionsSource
            .getUserAndExpandedPermissions(userId, tenant, okapiUrl, permissionsRequestToken,
            requestId, extraPermissions, cacheKey);
    logger.debug("Retrieving permissions for userid " + userId + " and expanding permissions");
    retrievedPermissionsFuture.setHandler(res -> {
      if(res.failed()) {
        long stopTime = System.currentTimeMillis();
        logger.error("Unable to retrieve permissions for " + username + ": "
                + res.cause().getMessage() + " request took " +
                (stopTime - startTime) + " ms");
        ctx.response()
                .setStatusCode(500)
                .putHeader(MODULE_TOKENS_HEADER, moduleTokens.encode());
        if (suppressErrorResponse) {
          ctx.response().end();
        } else {
          endText(ctx, 500, "Unable to retrieve permissions for user with id'"
                  + finalUserId + "': " +  res.cause().getLocalizedMessage());
        }
        return;
      }

      JsonArray permissions = new JsonArray();
      JsonArray userPermissions = res.result().getUserPermissions();
      for (Object o : userPermissions) {
        String permName = (String) o;
        if (!permissions.contains(permName)) {
          permissions.add(permName);
        }
      }
      JsonArray expandedExtraPermissions = res.result().getExpandedPermissions();
      for (Object o : expandedExtraPermissions) {
        String permName = (String) o;
        if (!permissions.contains(permName)) {
          permissions.add(permName);
        }
      }

      //Check that for all required permissions, we have them
      for (Object o : permissionsRequired) {
        if (!permissions.contains(o) &&
                !extraPermissions.contains(o)) {
          logger.error(permissions.encode() + "(user permissions) nor "
                  + extraPermissions.encode() + "(module permissions) do not contain "
                  + (String) o);
          ctx.response().putHeader(MODULE_TOKENS_HEADER, moduleTokens.encode());
          endText(ctx, 403, "Access requires permission: " + (String) o);
          return;
        }
      }

      //Remove all permissions not listed in permissionsRequired or permissionsDesired
      List<Object> deleteList = new ArrayList<>();
      for (Object o : permissions) {
        if (!permissionsRequired.contains(o) && !Util.arrayContainsGlob(permissionsDesired, (String) o)) {
          deleteList.add(o);
        }
      }

      for (Object o : deleteList) {
        permissions.remove(o);
      }

      //Create new JWT to pass back with request, include calling module field
      JsonObject claims = getClaims(authToken);

      if (ctx.request().headers().contains(CALLING_MODULE_HEADER)) {
        claims.put("calling_module", ctx.request().headers().get(CALLING_MODULE_HEADER));
      }

      String token = null;
      try {
        token = tokenCreator.createJWTToken(claims.encode());
      } catch(Exception e) {
        String message = String.format("Error creating access token: %s",
            e.getLocalizedMessage());
        logger.error(message);
        ctx.response().putHeader(MODULE_TOKENS_HEADER, moduleTokens.encode());
        endText(ctx, 500, "Error creating access token");
        return;
      }

      //Return header containing relevant permissions
      ctx.response()
              .setChunked(true)
              .setStatusCode(202)
              .putHeader(CONTENT_TYPE, "text/plain")
              .putHeader(PERMISSIONS_HEADER, permissions.encode())
              .putHeader(MODULE_TOKENS_HEADER, moduleTokens.encode())
              .putHeader("Authorization", "Bearer " + token)
              .putHeader(OKAPI_TOKEN_HEADER, token);
      if (finalUserId != null) {
        ctx.response().putHeader(USERID_HEADER, finalUserId);
      }

      ctx.response().end();
    });
  }

  public String extractToken(String authorizationHeader) {
    Pattern pattern = null;
    Matcher matcher = null;
    String authToken = null;
    if(authorizationHeader == null) { return null; }
    pattern = Pattern.compile("Bearer\\s+(.+)"); // Grab anything after 'Bearer' and whitespace
    matcher = pattern.matcher(authorizationHeader);
    if(matcher.find() && matcher.groupCount() > 0) {
      return matcher.group(1);
    }
    return null;
  }

  public static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  private String mintNewAuthToken(String tenant, JsonObject refreshTokenClaims)
      throws JOSEException, ParseException {
    JsonObject newJWTPayload = new JsonObject();
    long nowTime = Instant.now().getEpochSecond();
    newJWTPayload
        .put("sub", refreshTokenClaims.getString("sub"))
        .put("tenant", tenant)
        .put("iat", nowTime)
        .put("exp", nowTime + 600) //10 minute TTL
        .put("user_id", refreshTokenClaims.getString("user_id"));
    return tokenCreator.createJWTToken(newJWTPayload.encode());
  }

  protected String generateRefreshToken(String tenant, String userId, String address,
      String subject) throws JOSEException {
    JsonObject payload = new JsonObject();
    long nowTime = Instant.now().getEpochSecond();
    payload.put("user_id", userId)
        .put("address", address)
        .put("tenant", tenant)
        .put("sub", subject)
        .put("iat", nowTime)
        .put("exp", nowTime + (60 * 60 * 24))
        .put("jti", UUID.randomUUID().toString())
        .put("prn", "refresh");
    String refreshToken = tokenCreator.createJWEToken(payload.encode());
    return refreshToken;
  }

  private Future<Boolean> validateRefreshToken(JsonObject tokenClaims, RoutingContext ctx) {
    Future<Boolean> future = Future.future();
    try {
      String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
      if(!tenant.equals(tokenClaims.getString("tenant"))) {
        logger.error("Tenant mismatch for refresh token");
        future.complete(Boolean.FALSE);
        return future;
      }
      String address = ctx.request().remoteAddress().host();
      if(!address.equals(tokenClaims.getString("address"))) {
        logger.error("Issuing address does not match for refresh token");
        future.complete(Boolean.FALSE);
        return future;
      }
      Long nowTime = Instant.now().getEpochSecond();
      Long expiration = tokenClaims.getLong("exp");
      if(expiration < nowTime) {
        logger.error("Attempt to refresh with expired refresh token");
        future.complete(Boolean.FALSE);
        return future;
      }
      checkRefreshTokenRevoked(tokenClaims).setHandler(res -> {
        if(res.failed()) {
          logAndReturnError(res.cause());
          future.fail(res.cause());
        } else {
          if(res.result()) {
            logger.error("Attempt to refresh with revoked token");
            future.complete(Boolean.FALSE);
          } else {
            future.complete(Boolean.TRUE);
          }
        }
      });
    } catch(Exception e) {
      logAndReturnError(e);
      future.fail(e);
    }
    return future;
  }

  private Future<Boolean> checkRefreshTokenRevoked(JsonObject tokenClaims) {
    //Stub function until we implement a shared revocation list
    Future<Boolean> future = Future.future();
    future.complete(Boolean.FALSE);
    return future;
  }

  private JsonObject parseJsonObject(String encoded, String[] requiredMembers)
      throws AuthtokenException {
    JsonObject json = null;
    try {
      json = new JsonObject(encoded);
    } catch(Exception e) {
      throw new AuthtokenException(String.format("Unable to parse JSON %s: %s", encoded,
          e.getLocalizedMessage()));
    }
    if(json == null) {
      throw new AuthtokenException(String.format("Unable to parse %s into valid JSON", encoded));
    }
    for(String s : requiredMembers) {
      if(!json.containsKey(s)) {
        throw new AuthtokenException(String.format("Missing required member: '%s'", s));
      }
      if(json.getValue(s) == null) {
        throw new AuthtokenException(String.format("Null value for required member: '%s'", s));
      }
    }
    return json;
  }

}


class LimitedSizeQueue<K> extends ArrayList<K> {

  private final int maxSize;

  public LimitedSizeQueue(int size){
    this.maxSize = size;
  }

  @Override
  public boolean add(K k){
    boolean r = super.add(k);
    if (size() > maxSize) {
      removeRange(0, size() - maxSize - 1);
    }
    return r;
  }

  public K getYoungest() {
    return get(size() - 1);
  }

  public K getOldest() {
    return get(0);
  }
}
