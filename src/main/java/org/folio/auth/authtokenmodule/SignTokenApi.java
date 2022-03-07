package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.okapi.common.XOkapiHeaders;

import io.vertx.ext.web.openapi.RouterBuilder;

import org.folio.tlib.RouterCreator;

public class SignTokenApi implements RouterCreator {
  private static final Logger logger = LogManager.getLogger(AuthorizeApi.class);
  PermissionsSource permissionsSource;
  private TokenCreator tokenCreator;

  public SignTokenApi() {}

  public SignTokenApi(Vertx vertx, TokenCreator tc) {
    tokenCreator = tc;
    int permLookupTimeout = Integer.parseInt(System.getProperty("perm.lookup.timeout", "10"));
    permissionsSource = new ModulePermissionsSource(vertx, permLookupTimeout);
   }

   @Override
   public Future<Router> createRouter(Vertx vertx) {
    return RouterBuilder.create(vertx, "openapi/sign-token-1.0.yaml")
        .map(routerBuilder -> {
          handlers(vertx, routerBuilder);
          return routerBuilder.createRouter();
        });
   }

   private void handlers(Vertx vertx, RouterBuilder routerBuilder) {
    routerBuilder
        .operation("token")
        .handler(this::handleSignToken);
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

      // Tenant and okapiUrl are already checked in AuthorizeApi
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
      logger.debug("Payload to create signed token from is {}", payload.encode());

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

      logger.debug("Successfully created and signed token");

      JsonObject responseObject = new JsonObject().put("token", token.encodeAsJWT(tokenCreator));
      endJson(ctx, 201, responseObject.encode());
    } catch (Exception e) {
      endText(ctx, 400, e);
    }
  }

  // TODO move these somewhere more sensible.

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

}
