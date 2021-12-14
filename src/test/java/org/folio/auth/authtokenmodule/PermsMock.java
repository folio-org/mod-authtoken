package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author kurt
 */
public class PermsMock extends AbstractVerticle {

  private static final Logger logger = LogManager.getLogger("PermsMock");

  public static int handlePermsUsersStatusCode = 200;
  public static int handlePermsUsersPermissionsStatusCode = 200;
  public static int handlePermsPermissionsStatusCode = 200;
  public static boolean handlePermsUsersFail = false;
  public static boolean handlePermsUsersEmpty = false;
  public static boolean handlePermsUsersPermissionsFail = false;
  public static boolean handlePermsPermissionsFail = false;
  public static String SYS_PERM_SET = PermService.SYS_PERM_PREFIX + "permset";
  public static String SYS_PERM_SUB_01 = "sys.sub.01";
  public static String SYS_PERM_SUB_02 = "sys.sub.02";
  private static String PERM_NAME = "permissionName";
  private static String PERM_SUB = "subPermissions";

  public void start(Promise<Void> promise) {
    final int port = context.config().getInteger("port");

    Router router = Router.router(vertx);
    HttpServer server = vertx.createHttpServer();

    router.route("/perms/users/:id/permissions").handler(this::handlePermUsersPermissions);
    router.route("/perms/users").handler(this::handlePermsUsers);
    router.route("/perms/permissions").handler(this::handlePermsPermissions);
    router.route("/users/:id").handler(this::handleUsers);
    logger.info("Running PermsMock on port " + port);
    server.requestHandler(router).listen(port, result -> promise.handle(result.mapEmpty()));
  }

  private void handleUsers(RoutingContext context) {
    String id = context.pathParam("id");
    if (id.contentEquals("404")) {
      context.response().setStatusCode(404).end();
      return;
    }
    if (id.contentEquals("inactive")) {
      context.response().putHeader("Content-Type", "application/json")
          .end(new JsonObject().put("active", false).encode());
      return;
    }
    context.response().putHeader("Content-Type", "application/json")
        .end(new JsonObject().put("active", true).encode());
  }

  private void handlePermsUsers(RoutingContext context) {
    if (handlePermsUsersFail) {
      context.response()
        .setStatusCode(handlePermsUsersStatusCode)
        .putHeader("Content-type", "application/json")
        .end("{");
      return;
    }
    JsonArray ar = new JsonArray();
    if (!handlePermsUsersEmpty) {
      ar.add(new JsonObject()
        .put("id", "773cb9d1-1e4f-416f-ba16-686ddeb6c789")
        .put("userId", "007d31d2-1441-4291-9bb8-d6e2c20e399a")
        .put("permissions", new JsonArray()
          .add("extra.foobar")
          .add("extra.foofish")
        )
      );
    }
    JsonObject output = new JsonObject().put("permissionUsers", ar);
    context.response()
      .setStatusCode(handlePermsUsersStatusCode)
      .putHeader("Content-Type", "application/json")
      .end(output.encode());
  }

  private void handlePermUsersPermissions(RoutingContext context) {
    if (handlePermsUsersPermissionsFail) {
      context.response()
        .setStatusCode(handlePermsUsersPermissionsStatusCode)
        .putHeader("Content-type", "application/json")
        .end("{");
      return;
    }
    JsonObject output = new JsonObject().put("permissionNames",
      new JsonArray()
        .add("extra.foobar")
        .add("extra.foofish")
    )
      .put("totalRecords", 1);

    context.response()
      .setStatusCode(handlePermsUsersPermissionsStatusCode)
      .putHeader("Content-type", "application/json")
      .end(output.encode());
  }

  private void handlePermsPermissions(RoutingContext context) {

    // SYS permission is expanded individually and only once
    String perms = context.queryParams().get("query");
    if (perms != null) {
      if (perms.contains(SYS_PERM_SET)) {
        if (perms.indexOf(PERM_NAME) != perms.lastIndexOf(PERM_NAME)) {
          String msg = "SYS perm should be expaned individually: " + perms;
          logger.error(msg);
          context.response().setStatusCode(500).setStatusMessage(msg).end();
          return;
        }
        JsonObject permsResp = new JsonObject().put("permissions",
          new JsonArray().add(new JsonObject()
            .put(PERM_NAME, SYS_PERM_SET)
            .put(PERM_SUB, new JsonArray().add(SYS_PERM_SUB_01).add(SYS_PERM_SUB_02))));
        context.response().putHeader("Content-type", "application/json")
          .end(permsResp.encode());
        return;
      };
      if (perms.contains(SYS_PERM_SUB_01) || perms.contains(SYS_PERM_SUB_02)) {
        String msg = "SYS perm should be expanded only once: " + perms;
        logger.error(msg);
        context.response().setStatusCode(500).setStatusMessage(msg).end();
        return;
      }
    }

    if (handlePermsPermissionsFail) {
      context.response()
        .setStatusCode(handlePermsPermissionsStatusCode)
        .putHeader("Content-type", "application/json")
        .end("{");
      return;
    }
    JsonObject sub = new JsonObject()
      .put(PERM_NAME, "bar.second")
      .put(PERM_SUB, new JsonArray()
        .add("bar.sub")
        .add(new JsonObject()
          .put(PERM_NAME, "bar.sub2")
          .put(PERM_SUB, new JsonArray()
            .add("bar.sub.sub")
          )
        )
      );
    JsonObject output = new JsonObject().put("permissions", new JsonArray()
      .add(new JsonObject()
        .put(PERM_NAME, "bar.first"))
      .add(sub).add(sub) // same permissions twice on purpose
    );
    context.response()
      .setStatusCode(handlePermsPermissionsStatusCode)
      .putHeader("Content-type", "application/json")
      .end(output.encode());
  }

}
