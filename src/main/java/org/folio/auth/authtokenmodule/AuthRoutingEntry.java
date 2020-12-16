package org.folio.auth.authtokenmodule;

import com.nimbusds.jose.util.Base64;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.folio.auth.authtokenmodule.MainVerticle.MODULE_TOKENS_HEADER;
import static org.folio.auth.authtokenmodule.MainVerticle.OKAPI_TOKEN_HEADER;
import static org.folio.auth.authtokenmodule.MainVerticle.PERMISSIONS_HEADER;
import static org.folio.auth.authtokenmodule.MainVerticle.getClaims;

/**
 *
 * @author kurt This class defines the values needed to create a non-filter
 * endpoint in the authtoken module
 */
public class AuthRoutingEntry {

  private String endpoint;
  private List<String> requiredPermissions;
  private Handler<RoutingContext> handler;
  private static final Logger logger = LogManager.getLogger(AuthRoutingEntry.class);

  public AuthRoutingEntry(String endpoint, String[] requiredPermissions,
    Handler<RoutingContext> handler) {
    init(endpoint, new ArrayList<>(Arrays.asList(requiredPermissions)), handler);
  }

  private void init(String endpoint, List<String> requiredPermissions,
    Handler<RoutingContext> handler) {
    this.endpoint = endpoint;
    this.requiredPermissions = requiredPermissions;
    this.handler = handler;
  }

  /*
  Return true if we're handling the route, false if pass-thru
   */
  public boolean handleRoute(RoutingContext ctx, String authToken, String moduleTokens) {
    JsonObject claims = getClaims(authToken);
    JsonArray extraPermissions = claims.getJsonArray("extra_permissions");
    if (extraPermissions == null) {
      extraPermissions = new JsonArray();
    }
    if (!ctx.request().path().startsWith(endpoint)) {
      return false;
    }
    if (ctx.getBodyAsString() == null || ctx.getBodyAsString().isEmpty()) {
      logger.debug(String.format("No body found in request for %s, treating as filter", endpoint));
      //check for permissions
      extraPermissions = PermService.expandSystemPermissionsUsingCache(extraPermissions);
      boolean allFound = true;
      for (String perm : requiredPermissions) {
        if (!extraPermissions.contains(perm)) {
          allFound = false;
          break;
        }
      }
      if (!allFound) {
        logger.error(String.format("Insufficient permissions to access endpoint %s", endpoint));
        ctx.response()
          .setChunked(true)
          .setStatusCode(401)
          .end(String.format("Missing required module-level permissions for endpoint '%s'",
            endpoint));
      } else {
        String magicPermission = getMagicPermission(endpoint);
        ctx.response()
          .setChunked(true)
          .setStatusCode(202)
          .putHeader(PERMISSIONS_HEADER, new JsonArray().add(magicPermission).encode())
          .putHeader(OKAPI_TOKEN_HEADER, authToken)
          .putHeader(MODULE_TOKENS_HEADER, moduleTokens)
          .end();
      }
      return true;
    } else {
      logger.debug(String.format("Body found in request for %s, treating as request", endpoint));
      JsonArray requestPerms = null;
      String permissionsHeader = ctx.request().headers().get(PERMISSIONS_HEADER);
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
      boolean passThrough = false;
      if (requestPerms != null && requestPerms.contains(getMagicPermission(endpoint))) {
        passThrough = true;
      }
      if (passThrough) {
        logger.debug(String.format("Calling handler %s", handler.toString()));
        handler.handle(ctx);
      } else {
        logger.error(String.format("Missing assigned permission to access endpoint '%s'",
          endpoint));
        ctx.response()
          .setStatusCode(403)
          .end(String.format("Missing permissions to access endpoint '%s'", endpoint));
      }
      return true;
    }
  }

  private String getMagicPermission(String endpoint) {
    return String.format("%s.execute", Base64.encode(endpoint));
  }
}
