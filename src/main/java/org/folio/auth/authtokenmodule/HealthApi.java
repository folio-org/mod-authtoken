package org.folio.auth.authtokenmodule;

import org.folio.tlib.RouterCreator;
import org.folio.tlib.TenantInitHooks;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClient;

public class HealthApi implements RouterCreator, TenantInitHooks {
  public static final String CONTENT_TYPE = "Content-Type";

  @Override
  public Future<Router> createRouter(Vertx vertx, WebClient webClient) {
    Router router = Router.router(vertx);
    router.get("/admin/health").handler(this::handleAdminHealth);
    return Future.succeededFuture(router);
  }

  private void handleAdminHealth(RoutingContext ctx) {
    ctx.response().setStatusCode(200);
    ctx.response().putHeader(CONTENT_TYPE, "text/plain");
    ctx.response().end("OK");
  }
}
