package org.folio.auth.authtokenmodule.apis;

import com.nimbusds.jose.util.Base64;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.web.RoutingContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.okapi.common.XOkapiHeaders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

 /**
  * Any endpoints that this module needs to handle require that a route be defined for them. These
  * routes are managed by the RouteApi and called by the FilterApi.
  * @see RouteApi
  * @see FilterApi
  * @author kurt
  */
public class Route {
  private String endpoint;
  private List<String> requiredPermissions;
  private Handler<RoutingContext> handler;
  private static final Logger logger = LogManager.getLogger(Route.class);

  /**
   * Constructs a new route.
   * @param endpoint The endpoint that the route should match on.
   * @param requiredPermissions The permissions that are required for the route.
   * @param handler The handler for the route.
   */
  public Route(String endpoint, List<String> requiredPermissions, Handler<RoutingContext> handler) {
    this.endpoint = endpoint;
    this.requiredPermissions = requiredPermissions;
    this.handler = handler;
  }

  /**
   * Handle the route (process the request to the given endpoint).
   * @param ctx The current http context.
   * @param authToken The token in scope.
   * @param moduleTokens A string representation of the module tokens in scope.
   * @param expandedPermissions expanded permissions from token or header.
   * @return True if the route should be handled, otherwise false if a pass-through.
   */
  public boolean handleRoute(RoutingContext ctx, String authToken, String moduleTokens,
    JsonArray expandedPermissions) {
    if (!ctx.request().path().startsWith(endpoint)) {
      return false;
    }
    logger.debug("Handling route for endpoint {}", endpoint);
    JsonArray requestPerms = null;
    String permissionsHeader = ctx.request().headers().get(XOkapiHeaders.PERMISSIONS);
    // Vert.x 3.5.4 accepted null for JsonArray constructor; Vert.x 3.9.1 does not
    if (permissionsHeader != null) {
      try {
        requestPerms = new JsonArray(permissionsHeader);
      } catch (io.vertx.core.json.DecodeException dex) {
        logger.warn(String.format("Error parsing permissions header: %s",
          dex.getLocalizedMessage()));
        logger.warn(String.format("Headers are: %s", ctx.request().headers().toString()));
      }
    }

    // The first time this is called there won't be a magic permission yet so we don't yet call
    // the actual route but instead apply the magic perm.
    if (requestPerms != null && requestPerms.contains(getMagicPermission(endpoint))) {
      // If we've reached this code this is the second request and the magic perm exists.
      logger.debug("Magic perm found. Calling handler for {}", endpoint);
      handler.handle(ctx);
      return true;
    }
    // If we've reached this point, this is still the first time the method has been called so we
    // make sure the permissions exist.
    boolean allFound = true;
    for (String perm : requiredPermissions) {
      if (!expandedPermissions.contains(perm)) {
        allFound = false;
        break;
      }
    }
    if (!allFound) {
      logger.error("Insufficient permissions to access endpoint {}: {}", endpoint, requiredPermissions);
      ctx.response()
        .setChunked(true)
        .setStatusCode(401)
        .end(String.format("Missing required module-level permissions for endpoint '%s': %s",
          endpoint, String.join(", ", requiredPermissions)));
    } else {
      logger.debug("Responding with magic permission for route: {}", endpoint);

      // Finally respond with the magic perm header. This is the first request still.
      String magicPermission = getMagicPermission(endpoint);
      ctx.response()
        .setChunked(true)
        .setStatusCode(202)
        .putHeader(XOkapiHeaders.PERMISSIONS, new JsonArray().add(magicPermission).encode())
        .putHeader(XOkapiHeaders.TOKEN, authToken)
        .putHeader(XOkapiHeaders.MODULE_TOKENS, moduleTokens)
        .end();
    }
    return true;
  }

  private String getMagicPermission(String endpoint) {
    return String.format("%s.execute", Base64.encode(endpoint));
  }
}
