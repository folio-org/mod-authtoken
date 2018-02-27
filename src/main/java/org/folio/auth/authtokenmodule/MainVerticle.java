package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.impl.DummyPermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import java.util.Base64;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 *
 * @author kurt
 */
public class MainVerticle extends AbstractVerticle {

  // TODO - Use header names from Okapi.common
  private static final String PERMISSIONS_HEADER = "X-Okapi-Permissions";
  private static final String DESIRED_PERMISSIONS_HEADER = "X-Okapi-Permissions-Desired";
  private static final String REQUIRED_PERMISSIONS_HEADER = "X-Okapi-Permissions-Required";
  private static final String MODULE_PERMISSIONS_HEADER = "X-Okapi-Module-Permissions";
  private static final String EXTRA_PERMISSIONS_HEADER = "X-Okapi-Extra-Permissions";
  private static final String CALLING_MODULE_HEADER = "X-Okapi-Calling-Module";
  private static final String USERID_HEADER = "X-Okapi-User-Id";
  private static final String REQUESTID_HEADER = "X-Okapi-Request-Id";
  private static final String MODULE_TOKENS_HEADER = "X-Okapi-Module-Tokens";
  private static final String OKAPI_URL_HEADER = "X-Okapi-Url";
  private static final String OKAPI_TOKEN_HEADER = "X-Okapi-Token";
  private static final String OKAPI_TENANT_HEADER = "X-Okapi-Tenant";
  private static final String SIGN_TOKEN_PERMISSION = "auth.signtoken";
  private static final String SIGN_TOKEN_EXECUTE_PERMISSION = "auth.signtoken.execute";
  private static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";
  private static final String TOKEN_USER_ID_FIELD = "user_id";
  private static final String ZAP_CACHE_HEADER = "Authtoken-Refresh-Cache";

  private static int MAX_CACHED_TOKENS = 100; //Probably could be a LOT bigger

  PermissionsSource permissionsSource;
  private String okapiUrl;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private static final String PERMISSIONS_USER_READ_BIT = "perms.users.get";
  private static final String PERMISSIONS_PERMISSION_READ_BIT = "perms.permissions.get";
  private boolean suppressErrorResponse = false;
  private boolean cachePermissions = true;

  private TokenCreator tokenCreator;
  //private Map<String, CacheEntry> cacheMap;

  private LimitedSizeQueue<String> tokenCache;

  private String uniqueSecret = UUID.randomUUID().toString();
  private Map<String, String> permissionsRequestTokenMap;

  public void start(Future<Void> future) {
    Router router = Router.router(vertx);
    HttpServer server = vertx.createHttpServer();
    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    String keySetting = System.getProperty("jwt.signing.key");
    tokenCreator = new TokenCreator(keySetting);

    String suppressString = System.getProperty("suppress.error.response", "false");
    if(suppressString.equals("true")) {
      suppressErrorResponse = true;
    }
    
    String cachePermsString = System.getProperty("cache.permissions", "true");
    if(cachePermsString.equals("true")) {
      cachePermissions = true;
    } else {
      cachePermissions = false;
    }
    

    permissionsRequestTokenMap = new HashMap<>();
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
   * Handle a request to sign a new token
   * (Typically used by login module)
   */
  private void handleSignToken(RoutingContext ctx) {
    try {
      logger.debug("Token signing request from " +  ctx.request().absoluteURI());
      String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
      if(tenant == null) {
        ctx.response().setStatusCode(400);
        ctx.response().end("Missing header: " + OKAPI_TENANT_HEADER);
        return;
      }

      updateOkapiUrl(ctx);
      if(ctx.request().method() == HttpMethod.POST) {
        final String postContent = ctx.getBodyAsString();
        JsonObject json = null;
        JsonObject payload = null;
        try {
          json = new JsonObject(postContent);
        } catch(DecodeException dex) {
          ctx.response().setStatusCode(400);
          ctx.response().end("Unable to decode '" + postContent + "' as valid JSON");
          return;
        }
        try {
          payload = json.getJsonObject("payload");
        } catch(Exception e) {
          ctx.response().setStatusCode(400);
          ctx.response().end("Unable to find valid 'payload' field in: " + json.encode());
          return;
        }
        if(payload == null) {
          ctx.response().setStatusCode(400)
                  .end("Valid 'payload' field is required");
          return;
        }
        logger.debug("Payload to create token from is " + payload.encode());

        if(!payload.containsKey("sub")) {
          ctx.response().setStatusCode(400)
                  .end("Payload must contain a 'sub' field");
          return;
        }

        payload.put("tenant", tenant);
        String token = tokenCreator.createToken(payload.encode());

        ctx.response().setStatusCode(200)
                .putHeader("Authorization", "Bearer " + token)
                .putHeader(OKAPI_TOKEN_HEADER, token)
                .end(postContent);
        return;

      } else {
        ctx.response().setStatusCode(400)
                .end("Unsupported operation: " + ctx.request().method().toString());
        return;
      }
    } catch(Exception e) {
      String message = e.getLocalizedMessage();
      logger.error(message, e);
      ctx.response().setStatusCode(500)
              .end(message);
    }
  }

  private void handleAuthorize(RoutingContext ctx) {
    logger.debug("Calling handleAuthorize for " + ctx.request().absoluteURI());
    String requestId = ctx.request().headers().get(REQUESTID_HEADER);
    String userId = ctx.request().headers().get(USERID_HEADER);
    String tenant = ctx.request().headers().get(OKAPI_TENANT_HEADER);
    if(tenant == null) {
      ctx.response().setStatusCode(400);
      ctx.response().end("Missing header: " + OKAPI_TENANT_HEADER);
      return;
    }
    String zapCacheString = ctx.request().headers().get(ZAP_CACHE_HEADER);
    boolean zapCache = false;
    if(zapCacheString != null && zapCacheString.equals("true")) {
      zapCache = true;
    }
    
    updateOkapiUrl(ctx);
    //String requestToken = getRequestToken(ctx);
    String authHeader = ctx.request().headers().get("Authorization");
    String okapiTokenHeader = ctx.request().headers().get(OKAPI_TOKEN_HEADER);
    String candidateToken = null;
    if(okapiTokenHeader != null && authHeader != null) {
      String authToken = extractToken(authHeader);
      if(authToken.equals(okapiTokenHeader)) {
        candidateToken = authToken;
      } else {
        logger.error("Conflict between different auth headers");
        ctx.response().setStatusCode(400);
        ctx.response().end("Conflicting token information in Authorization and " +
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

    logger.debug("Setting tenant for permissions source to " + tenant);
    permissionsSource.setTenant(tenant);
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

      permissionsRequestToken = tokenCreator.createToken(permissionRequestPayload.encode());
    }

    permissionsSource.setRequestToken(permissionsRequestToken);
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
        logger.error("Error creating dummy token: " + e.getMessage());
        throw new RuntimeException(e);
      }
      candidateToken = tokenCreator.createToken(dummyPayload.encode());
    }
    final String authToken = candidateToken;
    logger.debug("Final authToken is " + authToken);
    try {
      if (!tokenCache.contains(authToken)) {
        tokenCreator.checkToken(authToken);
        tokenCache.add(authToken);
      }
    } catch (MalformedJwtException m) {
        logger.error("Malformed token: " + authToken, m);
        ctx.response().setStatusCode(401)
                .end("Invalid token format");
        return;
    } catch(SignatureException s) {
        logger.error("Invalid signature on token " + authToken, s);
        ctx.response().setStatusCode(401)
                .end("Invalid token signature");
        return;
    } catch(UnsupportedJwtException u) {
        logger.error("Unsupported JWT format", u);
        ctx.response().setStatusCode(401)
                .end("Invalid token format");
        return;
    }
    
    JsonObject tokenClaims = getClaims(authToken);
    logger.debug("Token claims are " + tokenClaims.encode());

    /*
      When the initial request comes in, as a filter, we require that the auth.signtoken
      permission exists in the module tokens. This means that even if a request has
      the permission in its permissions list, it cannot request a token unless
      it has been granted at the module level. If it passes the filter successfully,
      a new permission, auth.signtoken.execute is attached to the outgoing request
      which the /token handler will check for when it processes the actual request
    */
    if(ctx.request().path().startsWith("/token")) {
      JsonArray extraPermissions = tokenClaims.getJsonArray("extra_permissions");
      if(ctx.getBodyAsString() == null || ctx.getBodyAsString().isEmpty()) {
        logger.debug("Request for /token with no content, treating as filtering request");
        if(extraPermissions != null && extraPermissions.contains(SIGN_TOKEN_PERMISSION)) {
          logger.debug("Adding permissions header with '" + SIGN_TOKEN_EXECUTE_PERMISSION + "' permisison to request");
          ctx.response()
                  .setChunked(true)
                  .setStatusCode(202)
                  .putHeader(PERMISSIONS_HEADER, new JsonArray().add(SIGN_TOKEN_EXECUTE_PERMISSION).encode())
                  .putHeader(OKAPI_TOKEN_HEADER, authToken);
          ctx.response().end();
        } else {
          ctx.response()
                  .setStatusCode(401)
                  .end("Missing module-level permissions for token signing request");
        }
        return;
      } else {
        logger.debug("Payload detected, treating as token signing request");
        //Check for permissions
        JsonArray requestPerms = null;
        try {
          requestPerms = new JsonArray(ctx.request().headers().get(PERMISSIONS_HEADER));
        } catch(io.vertx.core.json.DecodeException dex) {
          //Eh, just leave it null
        }
        
        
        if( (requestPerms == null || !requestPerms.contains(SIGN_TOKEN_EXECUTE_PERMISSION)) &&
               (extraPermissions == null || !extraPermissions.contains(SIGN_TOKEN_PERMISSION)) ) {
          logger.error("Request for /token, but no permissions granted in header");
          ctx.response()
                  .setStatusCode(403)
                  .end("Missing permissions for token signing request");
          return;
        } else {
          handleSignToken(ctx);
          return;
        }
      }
    }

    String username = tokenClaims.getString("sub");
    String jwtTenant = tokenClaims.getString("tenant");
    if (jwtTenant == null || !jwtTenant.equals(tenant)) {
      logger.error("Expected tenant: " + tenant + ", got tenant: " + jwtTenant);
      ctx.response()
              .setStatusCode(403)
              .end("Invalid token for access");
      return;
    }

    String tokenUserId = tokenClaims.getString(TOKEN_USER_ID_FIELD);
    if(tokenUserId != null) {
      if (userId != null) {
        if (!userId.equals(tokenUserId)) {
          ctx.response().setStatusCode(403)
                  .end("Payload user id of '" + tokenUserId
                          + " does not match expected value.");
          return;
        }
      } else {
        //Assign the userId to be whatever's in the token
        userId = tokenUserId;
      }
    } else {
      logger.info("No '" + TOKEN_USER_ID_FIELD + "' field found in token");
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
    if(ctx.request().headers().contains(MODULE_PERMISSIONS_HEADER)) {
      JsonObject modulePermissions = new JsonObject(ctx.request().headers().get(MODULE_PERMISSIONS_HEADER));
      logger.debug("Recieved module permissions are " + modulePermissions.encode());
      for(String moduleName : modulePermissions.fieldNames()) {
        JsonArray permissionList = modulePermissions.getJsonArray(moduleName);
        JsonObject tokenPayload = new JsonObject();
        tokenPayload.put("sub", username);
        tokenPayload.put("tenant", tenant);
        tokenPayload.put("module", moduleName);
        tokenPayload.put("extra_permissions", permissionList);
        tokenPayload.put("request_id", requestId);
        tokenPayload.put("user_id", finalUserId);
        String moduleToken = tokenCreator.createToken(tokenPayload.encode());
        moduleTokens.put(moduleName, moduleToken);
     }
    }

    //Add the original token back into the module tokens
    moduleTokens.put("_", authToken);
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
    if(tokenClaims.getBoolean("dummy") != null || username.startsWith(UNDEFINED_USER_NAME)) {
      logger.debug("Using dummy permissions source");
      usePermissionsSource = new DummyPermissionsSource();
    } else {
      usePermissionsSource = permissionsSource;
    }
    
    if(zapCache && usePermissionsSource instanceof Cache) {
      logger.info("Requesting cleared cache for userid '" + userId + "'");
      ((Cache)usePermissionsSource).clearCache(userId);
    }

    //Retrieve the user permissions and populate the permissions header
    logger.debug("Getting user permissions for " + username + " (userId " +
            userId + ")");
    long startTime = System.currentTimeMillis();
    Future<PermissionData> retrievedPermissionsFuture;

    retrievedPermissionsFuture = usePermissionsSource.getUserAndExpandedPermissions(
            userId, extraPermissions);
    logger.info("Retrieving permissions for userid " + userId + ", and expanded permissions for " +
            extraPermissions.encode());
    retrievedPermissionsFuture.setHandler(res -> {
      if(res.failed()) {
        long stopTime = System.currentTimeMillis();
        logger.error("Unable to retrieve permissions for " + username + ": " + res.cause().getMessage() +
                " request took " + (stopTime - startTime) + " ms");
        ctx.response()
                .setStatusCode(500);
        if(suppressErrorResponse) {
          ctx.response().end();
        } else {
          ctx.response().end("Unable to retrieve permissions for user with id'" + finalUserId + "': " +  res.cause().getLocalizedMessage());
        }
        return;
      }
      
      JsonArray permissions = res.result().getUserPermissions();
      JsonArray expandedExtraPermissions = res.result().getExpandedPermissions();
      logger.debug("Permissions for " + username + ": " + permissions.encode());
      
      if(expandedExtraPermissions != null) {
        logger.debug("expandedExtraPermissions are: " + expandedExtraPermissions.encode());
        for (Object o : expandedExtraPermissions) {
          permissions.add((String) o);
        }
      }

      //Check that for all required permissions, we have them
      for (Object o : permissionsRequired) {
        if (!permissions.contains((String) o) && !extraPermissions.contains((String) o)) {
        //if(!arrayContainsGlob(permissions, (String) o) && !arrayContainsGlob(extraPermissions, (String) o)) {
          logger.error(permissions.encode() + "(user permissions) nor "
                  + extraPermissions.encode() + "(module permissions) do not contain " + (String) o);
          ctx.response()
                  .setStatusCode(403)
                  .end("Access requires permission: " + (String) o);
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

      String token = tokenCreator.createToken(claims.encode());

      logger.debug("Returning header " + PERMISSIONS_HEADER + " with content " + permissions.encode());
      logger.debug("Returning header " + MODULE_TOKENS_HEADER + " with content " + moduleTokens.encode());
      logger.debug("Returning Authorization Bearer token with content " + claims.encode());
      //Return header containing relevant permissions
      ctx.response()
              .setChunked(true)
              .setStatusCode(202)
              .putHeader(PERMISSIONS_HEADER, permissions.encode())
              .putHeader(MODULE_TOKENS_HEADER, moduleTokens.encode())
              .putHeader("Authorization", "Bearer " + token)
              .putHeader(OKAPI_TOKEN_HEADER, token);
      if (finalUserId != null) {
        ctx.response().putHeader(USERID_HEADER, finalUserId);
      }

      ctx.response().end();
      return;
    });
  }

  private void updateOkapiUrl(RoutingContext ctx) {
    if(ctx.request().getHeader(OKAPI_URL_HEADER) != null) {
      this.okapiUrl = ctx.request().getHeader(OKAPI_URL_HEADER);
      permissionsSource.setOkapiUrl(okapiUrl);
    }
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

  public JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  private String getRequestToken(RoutingContext ctx) {
    String token = ctx.request().headers().get(OKAPI_TOKEN_HEADER);
    logger.debug("Module request token from Okapi is: " + token);
    if(token == null) {
      return "";
    }
    return token;
  }

}


class LimitedSizeQueue<K> extends ArrayList<K> {

	private int maxSize;

	public LimitedSizeQueue(int size){
		this.maxSize = size;
	}

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
