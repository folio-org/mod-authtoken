package org.folio.auth.authtokenmodule.apis;

import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.MainVerticle;

public abstract class TokenApi {
  protected static Logger logger;

  protected static void endText(RoutingContext ctx, int code, String msg) {
    logger.error(msg);
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(MainVerticle.CONTENT_TYPE, "text/plain");
    ctx.response().end(msg);
  }

  protected static void endJson(RoutingContext ctx, int code, String msg) {
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON);
    ctx.response().end(msg);
  }

  protected static void endText(RoutingContext ctx, int code, String lead, Throwable t) {
    logger.error(lead, t);
    endText(ctx, code, lead + t.getLocalizedMessage());
  }

  protected static void endText(RoutingContext ctx, int code, Throwable t) {
    endText(ctx, code, "Error: ", t);
  }
}
