package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class UsersMock extends AbstractVerticle {

  public void start(Future<Void> future) {
    Router router = Router.router(vertx);
    router.route("/users/:id").handler(this::handleUser);

    HttpServer server = vertx.createHttpServer();
    int port = context.config().getInteger("port");
    server.requestHandler(router::accept).listen(port, result -> {
      if (result.failed()) {
        future.fail(result.cause());
      } else {
        future.complete();
      }
    });
  }

  private void handleUser(RoutingContext context) {
    String userId = context.request().getParam("id");
    // 404 for user id 0
    if (userId.contentEquals("0")) {
      context.response().setStatusCode(404).putHeader("Content-Type", "application/json").end();
      return;
    }
    // invalid response code for user id 00
    if (userId.contentEquals("00")) {
      context.response().setStatusCode(400).putHeader("Content-Type", "application/json").end();
      return;
    }
    // invalid response JSON for user id 000
    if (userId.contentEquals("000")) {
      context.response().setStatusCode(200).putHeader("Content-Type", "application/json")
          .end("invalid json");
      return;
    }
    // null for user id 1
    if (userId.contentEquals("1")) {
      context.response().setStatusCode(200).putHeader("Content-Type", "application/json")
          .end(new JsonObject().encode());
      return;
    }
    // inactive for user id 2
    if (userId.contentEquals("2")) {
      context.response().setStatusCode(200).putHeader("Content-Type", "application/json")
          .end(new JsonObject().put("active", false).encode());
      return;
    }
    // active for all other user ids
    context.response().setStatusCode(200).putHeader("Content-Type", "application/json")
        .end(new JsonObject().put("active", true).encode());
  }

}
