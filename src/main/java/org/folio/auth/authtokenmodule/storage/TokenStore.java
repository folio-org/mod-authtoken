package org.folio.auth.authtokenmodule.storage;

import java.util.UUID;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  protected Vertx vertx;
  protected String tenant;
  protected TenantPgPool pool;

  public TokenStore(Vertx vertx, String tenant) {
    this.vertx = vertx;
    this.tenant = tenant;
  }

  public Future<SqlConnection> connect() {
    pool = TenantPgPool.pool(vertx, tenant);
    return pool.getConnection();
  }

  protected Future<Void> checkTokenNotRevoked(SqlConnection conn, UUID tokenId, String tableNameSuffix) {
    log.info("Checking revoked status of {} token id {}", tableNameSuffix, tokenId);

    String select = "SELECT is_revoked FROM " + tableName(tenant, tableNameSuffix) + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return getRow(conn, select, where).compose(row -> {
      boolean isRevoked = row.getBoolean("is_revoked");

      log.info("Revoked status of {} token id {} is {}", tableNameSuffix, tokenId, isRevoked);

      if (!isRevoked) {
        return Future.succeededFuture();
      }
      return Future.failedFuture("Token is revoked");
    });
  }

  public Future<Row> getRow(SqlConnection conn, String select, Tuple where) {
    return conn.preparedQuery(select).execute(where).compose(rows -> {
      if (rows.rowCount() == 0) {
        String msg = "Token with id {} not found in token store";
        log.error(msg, where.toString());
        return Future.failedFuture("Token not found");
      }
      Row row = rows.iterator().next();
      return Future.succeededFuture(row);
    });
  }

  public String tableName(String tenant, String tableName) {
    return pool.getSchema() + "." + tableName + " ";
  }
}
