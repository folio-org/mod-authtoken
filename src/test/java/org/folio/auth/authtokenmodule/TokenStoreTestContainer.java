package org.folio.auth.authtokenmodule;

import io.vertx.pgclient.PgConnectOptions;
import org.folio.tlib.postgres.TenantPgPool;
import org.testcontainers.containers.PostgreSQLContainer;

public final class TokenStoreTestContainer {

  /**
   * Create PostgreSQL container for the TokenStore.
   * @return container.
   */
  public static PostgreSQLContainer<?> create() {
    return create("postgres:12-alpine");
  }

  /**
   * Create PostgreSQL container for the TokenStore.
   * @param image container image name.
   * @return container.
   */
  public static PostgreSQLContainer<?> create(String image) {
    PostgreSQLContainer<?> container = new PostgreSQLContainer<>(image);
    container.start();

    TenantPgPool.setDefaultConnectOptions(new PgConnectOptions()
        .setPort(container.getFirstMappedPort())
        .setHost(container.getHost())
        .setDatabase(container.getDatabaseName())
        .setUser(container.getUsername())
        .setPassword(container.getPassword()));
    return container;
  }
}
