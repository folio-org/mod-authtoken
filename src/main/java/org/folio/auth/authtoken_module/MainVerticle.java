package org.folio.auth.authtoken_module;

import org.folio.auth.authtoken_module.impl.DummyPermissionsSource;
import org.folio.auth.authtoken_module.impl.ModulePermissionsSource;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;


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
  private static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";
  private static final String TOKEN_USER_ID_FIELD = "user_id";

  PermissionsSource permissionsSource;
  private String okapiUrl;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private static final String PERMISSIONS_USER_READ_BIT = "perms.users.get";
  private static final String PERMISSIONS_PERMISSION_READ_BIT = "perms.permissions.get";
  private int permLookupTimeout;
  private boolean suppressErrorResponse = false;

  private TokenCreator tokenCreator;

  public void start(Future<Void> future) {
    Router router = Router.router(vertx);
    HttpServer server = vertx.createHttpServer();
    permLookupTimeout =Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    String keySetting = System.getProperty("jwt.signing.key");
    tokenCreator = new TokenCreator(keySetting);

    String suppressString = System.getProperty("suppress.error.response", "false");
    if(suppressString.equals("true")) {
      suppressErrorResponse = true;
    }

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
    permissionsSource = new ModulePermissionsSource(vertx);
    //permissionsSource = new DummyPermissionsSource();

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

    logger.debug("AuthZ> Setting tenant for permissions source to " + tenant);
    permissionsSource.setTenant(tenant);

    /*
      In order to make our request to the permissions module
      we generate a custom token (since we have that power) that
      has the necessary permissions in it. This prevents an
      ugly 'lookup loop'

    TODO: Make the permissions read permission configurable,
    rather than hardcoded
    */
    JsonObject permissionRequestPayload = new JsonObject()
                .put("sub", "_AUTHZ_MODULE_")
                .put("tenant", tenant)
                .put("dummy", true)
                .put("request_id", requestId)
                .put("extra_permissions", new JsonArray()
                		.add(PERMISSIONS_PERMISSION_READ_BIT)
                		.add(PERMISSIONS_USER_READ_BIT));

    String permissionsRequestToken = tokenCreator.createToken(permissionRequestPayload.encode());

    permissionsSource.setRequestToken(permissionsRequestToken);
    permissionsSource.setRequestTimeout(permLookupTimeout);
    if(candidateToken == null) {
      logger.info("AuthZ> Generating dummy authtoken");
      JsonObject dummyPayload = new JsonObject();
      try {
        logger.debug("AuthZ> Generating a dummy token");
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
        logger.error("AuthZ> Error creating dummy token: " + e.getMessage());
        throw new RuntimeException(e);
      }
      candidateToken = tokenCreator.createToken(dummyPayload.encode());
    }
    final String authToken = candidateToken;
    logger.debug("AuthZ> Final authToken is " + authToken);
    try {
      tokenCreator.checkToken(authToken);
    } catch (MalformedJwtException m) {
        logger.error("Malformed token", m);
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

    logger.debug("AuthZ> Token claims are " + getClaims(authToken).encode());

    /*
    Here, we're really basically saying that we are only going to allow access
    to the /token endpoint if the request has a module-level permission defined
    for it. There really should be no other case for this endpoint to be accessed
    */

    JsonObject tokenClaims = getClaims(authToken);

    if(ctx.request().path().startsWith("/token")) {
      JsonArray extraPermissions = tokenClaims.getJsonArray("extra_permissions");
      if(extraPermissions == null || !extraPermissions.contains(SIGN_TOKEN_PERMISSION)) {
        //do nothing
      } else {
        handleSignToken(ctx);
        return;
      }
    }

    String username = tokenClaims.getString("sub");
    String jwtTenant = tokenClaims.getString("tenant");
    if (jwtTenant == null || !jwtTenant.equals(tenant)) {
      logger.error("AuthZ> Expected tenant: " + tenant + ", got tenant: " + jwtTenant);
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
      logger.debug("AuthZ> Extra permissions from " + EXTRA_PERMISSIONS_HEADER
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
      logger.debug("AuthZ> Recieved module permissions are " + modulePermissions.encode());
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
      logger.debug("AuthZ> Using dummy permissions source");
      usePermissionsSource = new DummyPermissionsSource();
    } else {
      usePermissionsSource = permissionsSource;
    }

    //Retrieve the user permissions and populate the permissions header
    logger.debug("AuthZ> Getting user permissions for " + username + " (userId " +
            userId + ")");
    long startTime = System.currentTimeMillis();
    usePermissionsSource.getPermissionsForUser(userId).setHandler((AsyncResult<JsonArray> res) -> {
      if(res.failed()) {
        long stopTime = System.currentTimeMillis();
        logger.error("AuthZ> Unable to retrieve permissions for " + username + ": " + res.cause().getMessage() +
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
      JsonArray permissions = res.result();
      logger.debug("AuthZ> Permissions for " + username + ": " + permissions.encode());
      logger.debug("AuthZ> Extra permissions for request: " + extraPermissions.encode());
      usePermissionsSource.expandPermissions(extraPermissions).setHandler( res2 -> {
      	if(res2.failed()) {
          String message = "Error getting expanded permissions for " +
                  extraPermissions.encode() + " : " + res2.cause().getLocalizedMessage();
          ctx.response().setStatusCode(500)
                  .end(message);
          logger.error(message, res2.cause());
        } else {
          JsonArray expandedExtraPermissions = res2.result();
          if(expandedExtraPermissions != null) {
            logger.debug("AuthZ> expandedExtraPermissions are: " + expandedExtraPermissions.encode());
            for (Object o : expandedExtraPermissions) {
              permissions.add((String) o);
            }
          }

          //Check that for all required permissions, we have them
          for (Object o : permissionsRequired) {
            if (!permissions.contains((String) o) && !extraPermissions.contains((String) o)) {
            //if(!arrayContainsGlob(permissions, (String) o) && !arrayContainsGlob(extraPermissions, (String) o)) {
              logger.error("Authz> " + permissions.encode() + "(user permissions) nor "
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

          logger.debug("AuthZ> Returning header " + PERMISSIONS_HEADER + " with content " + permissions.encode());
          logger.debug("AuthZ> Returning header " + MODULE_TOKENS_HEADER + " with content " + moduleTokens.encode());
          logger.debug("AuthZ> Returning Authorization Bearer token with content " + claims.encode());
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

          ctx.response().end(ctx.getBodyAsString());
          return;
        }
      });
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
    logger.debug("AuthZ> Module request token from Okapi is: " + token);
    if(token == null) {
      return "";
    }
    return token;
  } 
  
}
