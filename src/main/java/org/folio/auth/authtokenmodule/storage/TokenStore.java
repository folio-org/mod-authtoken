package org.folio.auth.authtokenmodule.storage;

import java.util.UUID;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  protected Vertx vertx;

  public TokenStore(Vertx vertx) {
    this.vertx = vertx;
  }

  protected Future<Void> checkTokenNotRevoked(String tenant, UUID tokenId, String tableNameSuffix) {
    log.info("Checking revoked status of {} token id {}", tableNameSuffix, tokenId);

    String select = "SELECT is_revoked FROM " + tableName(tenant, tableNameSuffix) + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return withPool(tenant, pool -> pool.preparedQuery(select).execute(where)).compose(rows -> {
      if (rows.rowCount() == 0) {
        String msg = "Token with id {} not found in {} token store. Token is treated as revoked.";
        log.error(msg, tokenId, tableNameSuffix);
        return Future.failedFuture("Token not found");
      }
      Row row = rows.iterator().next();
      Boolean isRevoked = row.getBoolean("is_revoked");

      log.info("Revoked status of {} token id {} is {}", tableNameSuffix, tokenId, isRevoked);

      if (!isRevoked) {
        return Future.succeededFuture();
      }
      return Future.failedFuture("Token is revoked");
    });
  }

  protected String tableName(String tenant, String tableName) {
    return getSchema(tenant) + "." + tableName + " ";
  }

  // NOTE: TenantPgPool exposes a method for this, but that makes using the
  // withPool method impossible since if we use TenantPgPool.getSchema
  // the pool needs to be constructed prior to calling apply using the mapper.
  protected String getSchema(String tenant) {
    return tenant + "_mod_authtoken";
  }

  protected <T> Future<T> withPool(String tenant, Function<TenantPgPool, Future<T>> mapper) {
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    Future<T> future = mapper.apply(pool);
    return future.eventually(x -> pool.close());
  }
}
