package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

/**
 *
 * @author kurt
 */
public class PermsMock extends AbstractVerticle {

  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");

  public static int handlePermsUsersStatusCode = 200;
  public static int handlePermsPermissionsStatusCode = 200;
  public static int handlePermsUsersPermissionsStatusCode = 200;
  public static boolean handlePermsPermissionsFail = false;

  public void start(Future<Void> future) {
    final int port = context.config().getInteger("port");

    Router router = Router.router(vertx);
    HttpServer server = vertx.createHttpServer();

    router.route("/perms/users/:id/permissions").handler(this::handlePermUsersPermissions);
    router.route("/perms/users").handler(this::handlePermsUsers);
    router.route("/perms/permissions").handler(this::handlePermsPermissions);
    logger.info("Running PermsMock on port " + port);
    server.requestHandler(router::accept).listen(port, result -> {
      if (result.failed()) {
        future.fail(result.cause());
      } else {
        future.complete();
      }
    });
  }

  private void handlePermsUsers(RoutingContext context) {
    JsonObject output = new JsonObject().put("permissionUsers", new JsonArray()
      .add(new JsonObject()
        .put("id", "773cb9d1-1e4f-416f-ba16-686ddeb6c789")
        .put("userId", "007d31d2-1441-4291-9bb8-d6e2c20e399a")
        .put("permissions", new JsonArray()
          .add("extra.foobar")
          .add("extra.foofish")
        )
      )
    );

    context.response()
      .setStatusCode(handlePermsUsersStatusCode)
      .putHeader("Content-Type", "application/json")
      .end(output.encode());

  }

  private void handlePermUsersPermissions(RoutingContext context) {
    JsonObject output = new JsonObject().put("permissionNames",
      new JsonArray()
        .add("extra.foobar")
        .add("extra.foofish")
    )
      .put("totalRecords", 1);

    context.response()
      .setStatusCode(handlePermsUsersPermissionsStatusCode)
      .end(output.encode());
  }

  private void handlePermsPermissions(RoutingContext context) {
    if (handlePermsPermissionsFail) {
      context.response()
        .setStatusCode(handlePermsPermissionsStatusCode)
        .putHeader("Content-type", "application/json")
        .end("{");
      return;
    }
    JsonObject sub = new JsonObject()
      .put("permissionName", "bar.second")
      .put("subPermissions", new JsonArray()
        .add("bar.sub")
        .add(new JsonObject()
          .put("permissionName", "bar.sub2")
          .put("subPermissions", new JsonArray()
            .add("bar.sub.sub")
          )
        )
      );
    JsonObject output = new JsonObject().put("permissions", new JsonArray()
      .add(new JsonObject()
        .put("permissionName", "bar.first"))
      .add(sub).add(sub) // same permissions twice on purpose
    );
    context.response()
      .setStatusCode(handlePermsPermissionsStatusCode)
      .putHeader("Content-type", "application/json")
      .end(output.encode());
  }

}
