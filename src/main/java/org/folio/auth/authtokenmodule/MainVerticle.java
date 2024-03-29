package org.folio.auth.authtokenmodule;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpServerOptions;
import org.folio.tlib.api.HealthApi;
import org.folio.auth.authtokenmodule.apis.FilterApi;
import org.folio.auth.authtokenmodule.apis.RouteApi;
import org.folio.tlib.RouterCreator;
import org.folio.tlib.api.Tenant2Api;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;
import com.nimbusds.jose.JOSEException;

import org.folio.tlib.postgres.TenantPgPool;

public class MainVerticle extends AbstractVerticle {
  public static final String APPLICATION_JSON = "application/json";
  public static final String CONTENT_TYPE = "Content-Type";
  public static final String ACCEPT = "Accept";
  public static final String ZAP_CACHE_HEADER = "Authtoken-Refresh-Cache";

  TokenCreator getTokenCreator() throws JOSEException {
    String keySetting = System.getProperty("jwt.signing.key");
    return new TokenCreator(keySetting);
  }

  private UserService userService;
  private TokenCreator tokenCreator;

  @Override
  public void start(Promise<Void> promise) throws MissingAlgorithmException {
    TenantPgPool.setModule("mod-authtoken");

    // Get the port from context too, the unit test needs to set it there.
    final String defaultPort = context.config().getString("port", "8081");
    final String portStr = System.getProperty("http.port", System.getProperty("port", defaultPort));
    final int port = Integer.parseInt(portStr);
    int userCacheInSeconds = Integer.parseInt(System.getProperty("user.cache.seconds", "60")); // 1 minute
    int userCachePurgeInSeconds = Integer.parseInt(System.getProperty("user.cache.purge.seconds", "43200")); // 12 hours

    setLogLevel(System.getProperty("log.level", null));

    try {
      tokenCreator = getTokenCreator();
      tokenCreator.dryRunAlgorithms();
    } catch(Exception e) {
      throw new MissingAlgorithmException("Unable to initialize TokenCreator: " + e.getMessage(), e);
    }

    userService = new UserService(vertx, userCacheInSeconds, userCachePurgeInSeconds);

    // Define the routes that this module must handle.
    var routeApi = new RouteApi(vertx, tokenCreator, userService);

    // Define the filter api which fires for every request to this module, passing in the route
    // API object, because the filter API depends on it.
    var filterApi = new FilterApi(vertx, tokenCreator, routeApi, userService);

    // NOTE The order of adding these RouterCreator objects is important for the proper functioning
    // of this module.
    RouterCreator[] routerCreators = {
      new HealthApi(), // Called regardless of tenant. Can be called first since it isn't secured.
      filterApi,  // Filtering happens next. Only then can non-filter endpoints be called.
      new Tenant2Api(routeApi), // Causes postInit to be called (and database creation to happen).
      routeApi, // Must be called last for all of the openapi magic to work.
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

  // Suppress SonarCloud security hotspot warning:
  // "Configuring loggers is security-sensitive"
  // https://sonarcloud.io/organizations/folio-org/rules?open=java%3AS4792&rule_key=java%3AS4792
  @java.lang.SuppressWarnings({"squid:S4792"})
  static Level setLogLevel(Level level) {
    Level existing = LogManager.getRootLogger().getLevel();
    Configurator.setAllLevels(LogManager.getRootLogger().getName(), level);
    return existing;
  }

}
