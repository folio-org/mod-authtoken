package org.folio.auth.authtokenmodule.storage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

/**
 * The base class for all token storage. Actual token store classes should
 * extend this.
 */
public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  protected Vertx vertx;
  protected String tenant;
  protected TenantPgPool pool;

  public TokenStore(Vertx vertx, String tenant) {
    this.vertx = vertx;
    this.tenant = tenant;
    this.pool = TenantPgPool.pool(vertx, tenant);
  }


  protected Future<Void> removeAll(String suffix) {
    log.info("Removing all tokens from storage");

    String delete = "DELETE FROM " + tableName(tenant, suffix);

    return pool.preparedQuery(delete).execute().mapEmpty();
  }

  protected Future<Row> getRow(SqlConnection conn, String select, Tuple where) {
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

  protected Future<RowSet<Row>> getRows(String select) {
    return pool.preparedQuery(select).execute();
  }

  protected String tableName(String tenant, String tableName) {
    return pool.getSchema() + "." + tableName + " ";
  }
}
