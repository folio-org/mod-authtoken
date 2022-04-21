package org.folio.auth.authtokenmodule.apis;

import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.MainVerticle;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;

/**
 * Shared code which API classes can use.
 */
public abstract class Api {
  protected static Logger logger;

  protected static void endText(RoutingContext ctx, int code, String json) {
    logger.error(json);
    ctx.response().setStatusCode(code);
    ctx.response().putHeader(MainVerticle.CONTENT_TYPE, "text/plain");
    ctx.response().end(json);
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

  protected void handleTokenValidationFailure(Throwable h, RoutingContext ctx) {
    if (h instanceof TokenValidationException) {
      var e = (TokenValidationException)h;
      // Log the specific message for administrators.
      logger.error("Token validation failure: {}", e.getMessage(), h);
      // Return a generic message to clients.
      endText(ctx, e.getHttpResponseCode(), "Invalid token");
      return;
    }
    logger.error("Unexpected exception during token validation: {}", h.getMessage(), h);
    endText(ctx, 500, "Unexpected exception during token validation");
  }
}
