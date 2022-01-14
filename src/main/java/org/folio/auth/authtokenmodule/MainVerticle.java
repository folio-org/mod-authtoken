package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServerOptions;
import org.folio.tlib.RouterCreator;
import io.vertx.ext.web.client.WebClient;

/**
 *
 * @author kurt
 */
public class MainVerticle extends AbstractVerticle {

  public static final String APPLICATION_JSON = "application/json";
  public static final String CONTENT_TYPE = "Content-Type";
  public static final String ACCEPT = "Accept";
  static final String ZAP_CACHE_HEADER = "Authtoken-Refresh-Cache";

  @Override
  public void start(Promise<Void> promise) {
    // Get the port from context too, the unit test needs to set it there.
    final String defaultPort = context.config().getString("port", "8081");
    final String portStr = System.getProperty("http.port", System.getProperty("port", defaultPort));
    final int port = Integer.parseInt(portStr);

    // TODO How to also bind the body ahdnler.
    //router.route("/*").handler(BodyHandler.create());

    RouterCreator[] routerCreators = {
      new HealthApi(),
      new AuthorizeApi(vertx)
    };
    HttpServerOptions so = new HttpServerOptions()
        .setHandle100ContinueAutomatically(true);

    RouterCreator.mountAll(vertx, WebClient.create(vertx), routerCreators)
        .compose(route ->
            vertx.createHttpServer(so)
            .requestHandler(route)
            .listen(port)
            .mapEmpty())
        .<Void>mapEmpty()
        .onComplete(promise);
  }
}
