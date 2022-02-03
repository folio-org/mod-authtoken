package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServerOptions;
import org.folio.tlib.api.HealthApi;
import org.folio.tlib.RouterCreator;
import org.folio.tlib.api.Tenant2Api;

import io.vertx.ext.web.client.WebClient;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;
import com.nimbusds.jose.JOSEException;

import org.folio.tlib.postgres.TenantPgPool;

public class MainVerticle extends AbstractVerticle {

  public static final String APPLICATION_JSON = "application/json";
  public static final String CONTENT_TYPE = "Content-Type";
  public static final String ACCEPT = "Accept";
  static final String ZAP_CACHE_HEADER = "Authtoken-Refresh-Cache";

  TokenCreator getTokenCreator() throws JOSEException {
    String keySetting = System.getProperty("jwt.signing.key");
    return new TokenCreator(keySetting);
  }

  private TokenCreator tokenCreator;

  @Override
  public void start(Promise<Void> promise) throws MissingAlgorithmException {
    // TODO Determine if this is the best placet to do this. Would rather do it inside of TokenStore for example.
    TenantPgPool.setModule("mod-authtoken");

    // Get the port from context too, the unit test needs to set it there.
    final String defaultPort = context.config().getString("port", "8081");
    final String portStr = System.getProperty("http.port", System.getProperty("port", defaultPort));
    final int port = Integer.parseInt(portStr);

    setLogLevel(System.getProperty("log.level", null));

    try {
      tokenCreator = getTokenCreator();
      tokenCreator.dryRunAlgorithms();
    } catch(Exception e) {
      throw new MissingAlgorithmException("Unable to initialize TokenCreator: " + e.getMessage(), e);
    }

    var authorizeApi = new AuthorizeApi(vertx, tokenCreator);
    RouterCreator[] routerCreators = {
      // TODO Make it more clear here what is going on.
      // NOTE Adding these in this order is important.
      new HealthApi(),
      new Tenant2Api(authorizeApi),
      authorizeApi,
    };
    HttpServerOptions so = new HttpServerOptions().setHandle100ContinueAutomatically(true);

    RouterCreator.mountAll(vertx, routerCreators)
        .compose(route ->
            vertx.createHttpServer(so)
            .requestHandler(route)
            .listen(port)
            .mapEmpty())
        .<Void>mapEmpty()
        .onComplete(promise);
  }

  static void setLogLevel(String name) {
    if (name == null) {
      return;
    }
    setLogLevel(Level.toLevel(name));
  }

  static Level setLogLevel(Level level) {
    Level existing = LogManager.getRootLogger().getLevel();
    Configurator.setAllLevels(LogManager.getRootLogger().getName(), level);
    return existing;
  }

}
