package org.folio.auth.authtokenmodule.apis;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.folio.auth.authtokenmodule.MainVerticle;
import org.folio.auth.authtokenmodule.PermService;
import org.folio.auth.authtokenmodule.PermissionData;
import org.folio.auth.authtokenmodule.PermissionsSource;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.UserService;
import org.folio.auth.authtokenmodule.Util;
import org.folio.auth.authtokenmodule.impl.DummyPermissionsSource;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.ModuleToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.okapi.common.OkapiToken;
import org.folio.okapi.common.XOkapiHeaders;
import org.folio.okapi.common.logging.FolioLoggingContext;

import org.folio.tlib.RouterCreator;

import static java.lang.Boolean.TRUE;

/**
 * Filters every request in order to manage token authorization system-wide. Also handles calling
 * any routes that mod-authtoken has responsibility for. This route handling is managed by the
 * RouteApi, which this class has as a dependency.
 * @see RouteApi
 * @author kurt
 */
public class FilterApi extends Api implements RouterCreator {

  private static final String MISSING_HEADER = "Missing header: ";
  private static final String EXTRA_PERMS = "extra_permissions";
  private static final String PERMISSIONS_USER_READ_BIT = "perms.users.get";
  private static final String PERMISSIONS_PERMISSION_READ_BIT = "perms.permissions.get";
  private static final String PERMISSIONS_USERS_ITEM_GET = "users.item.get";

  private PermissionsSource permissionsSource;
  private UserService userService;
  private PermService permService;
  private TokenCreator tokenCreator;
  private RouteApi routeApi;

  public FilterApi() {}

  /**
   * Constructs the API.
   * @param vertx A reference to the current Vertx object.
   * @param tokenCreator A reference to the token creator which is shared among API objects.
   * @param routeApi A reference to the RouteApi object, which this API depends on for route
   * handling.
   */
  public FilterApi(Vertx vertx, TokenCreator tokenCreator, RouteApi routeApi) {
    logger = LogManager.getLogger(FilterApi.class);
    this.tokenCreator = tokenCreator;
    this.routeApi = routeApi;

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
    // NOTE These wildcard routes cause this API to act as a filter for every request, meaning
    // handleAuthorize will be called on every request.
    router.route("/*").handler(BodyHandler.create());
    router.route("/*").handler(this::handleAuthorize);
    return Future.succeededFuture(router);
  }

  private void handleAuthorize(RoutingContext ctx) {
    logger.debug("handleAuthorize path={}", () -> ctx.request().path());
    String requestId = ctx.request().headers().get(XOkapiHeaders.REQUEST_ID);
    String userId = ctx.request().headers().get(XOkapiHeaders.USER_ID);
    String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
    FolioLoggingContext.put(FolioLoggingContext.REQUEST_ID_LOGGING_VAR_NAME, requestId);
    FolioLoggingContext.put(FolioLoggingContext.MODULE_ID_LOGGING_VAR_NAME, "mod-authtoken");
    FolioLoggingContext.put(FolioLoggingContext.TENANT_ID_LOGGING_VAR_NAME, tenant);
    FolioLoggingContext.put(FolioLoggingContext.USER_ID_LOGGING_VAR_NAME, userId);

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

    // The candidate token will either be present or null. If it is null a dummy token
    // is assigned.
    String candidateToken = ctx.request().headers().get(XOkapiHeaders.TOKEN);
    final boolean isDummyToken = candidateToken == null;
    if (isDummyToken) {
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
      handleTokenValidationFailure(h, ctx);
    });

    tokenValidationResult.onSuccess(token -> {
      logger.debug("Validated token of type: {}", token.getClaim("type"));
      logger.debug("payload {}", () ->
        new OkapiToken(authToken).getPayloadWithoutValidation().encodePrettily());

      String username = token.getClaim("sub");

      // At this point, since we have validated what we can, if there is no userId
      // in the header, we can get the userId from the token.
      final String finalUserId = userId != null ? userId : token.getClaim("user_id");

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
      permService.expandSystemPermissions(extraPermissions, tenant, okapiUrl, permissionsRequestToken,
        requestId).onSuccess(expandedPermissions -> {
        // Instead of storing tokens, let's store an array of objects that each

        logger.debug("Handling module tokens");

        JsonObject moduleTokens = new JsonObject();
        /* TODO get module permissions (if they exist) */
        if (ctx.request().headers().contains(XOkapiHeaders.MODULE_PERMISSIONS)) {
          String modPermsHeader = ctx.request().headers().get(XOkapiHeaders.MODULE_PERMISSIONS);
          logger.debug("Module permissions from X-Okapi-Module-Permissions header: {}", modPermsHeader);
          JsonObject modulePermissions = new JsonObject(modPermsHeader);
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
         * When the initial request comes in, as a filter, we require that the auth.signtoken
         * permission exists in the module tokens. This means that even if a request has
         * the permission in its permissions list, it cannot request a token unless
         * it has been granted at the module level. If it passes the filter successfully,
         * a new permission, auth.signtoken.execute is attached to the outgoing request
         * which the /token/.. handlers will check for when it processes the actual request
         */
        if (routeApi.tryHandleRoute(ctx, authToken, moduleTokens.encode(), expandedPermissions)) {
          logger.debug("Handled mod-authtoken route request");
          return;
        }

        logger.debug("No route found. Proceeding with filter request.");

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
          logger.debug("Using dummy permissions source for token type: {}", token.getClaim("type"));
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

        // Need to check if the user is still active.
        Future<Boolean> activeUser = Future.succeededFuture(Boolean.TRUE);
        if (token.shouldCheckIfUserIsActive(finalUserId)) {
          activeUser = userService.isActiveUser(finalUserId, tenant, okapiUrl, userRequestToken, requestId);
        }
        Future<PermissionData> retrievedPermissionsFuture = activeUser.compose(b -> {
          if (TRUE.equals(b)) {
            JsonArray extraPermsMinusSystemOnes = new JsonArray();
            extraPermissions.forEach(it -> {
              if (!((String) it).startsWith(PermService.SYS_PERM_PREFIX)) {
                extraPermsMinusSystemOnes.add(it);
              }
            });
            return usePermissionsSource.getUserAndExpandedPermissions(finalUserId, tenant, okapiUrl,
              permissionsRequestToken, requestId, extraPermsMinusSystemOnes);
          } else {
            String msg = String.format("Invalid token: user with id %s is not active", finalUserId);
            endText(ctx, 401, msg);
            return Future.failedFuture(msg);
          }
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
          mergePerms(permissions, expandedPermissions);

          // Check that for all required permissions, we have them
          for (Object o : permissionsRequired) {
            if (!permissions.contains(o)
              && !extraPermissions.contains(o)) {
              String msg;
              if (isDummyToken) {
                msg = "Token missing, access requires permission: " + o;
              } else {
                msg = "Access for user '" + username + "' (" + finalUserId + ") requires permission: " + o;
              }

              logger.error(() -> "Permission missing in "
                + permissions.encode() + " (user permissions) and "
                + extraPermissions.encode() + " (module permissions). "
                + msg);
              // mod-authtoken should return the module tokens header even in case of errors.
              // If not, pre+post filters will NOT get modulePermissions from Okapi
              ctx.response().putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens.encode());
              endText(ctx, 403, msg);
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
            .putHeader(XOkapiHeaders.TOKEN, finalToken);

          if (finalUserId != null) {
            ctx.response().putHeader(XOkapiHeaders.USER_ID, finalUserId);
          }

          ctx.response().end();
        });
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
}
