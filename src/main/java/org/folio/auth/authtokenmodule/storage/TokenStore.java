package org.folio.auth.authtokenmodule.storage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

/**
 * The base class for all token storage.
 */
public abstract class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  protected TenantPgPool pool;

  public TokenStore(Vertx vertx, String tenant) {
    this.pool = TenantPgPool.pool(vertx, tenant);
  }

  protected Future<Void> removeAll(String suffix) {
    log.info("Removing all tokens from storage");

    String delete = "DELETE FROM " + tableName(suffix);

    return pool.preparedQuery(delete).execute().mapEmpty();
  }

  /**
   * Fetch a single row for the given sql and parameters.
   * @param sql The sql statement.
   * @param parameters A Tuple for the sql parameters.
   * @return A single row. If the query results in multiple rows, all other rows are ignored.
   * Caller may append LIMIT 1 to speed up the query.
   */
  protected Future<Row> getRow(String sql, Tuple parameters) {
    return pool.preparedQuery(sql).execute(parameters).compose(rows -> {
      if (rows.rowCount() == 0) {
        String msg = "Token with id {} not found in token store";
        log.error(msg, parameters.toString());
        return Future.failedFuture("Token not found. It is considered revoked.");
      }
      Row row = rows.iterator().next();
      return Future.succeededFuture(row);
    });
  }

  protected Future<RowSet<Row>> getRows(String select) {
    return pool.preparedQuery(select).execute();
  }

  /**
   * Gets the fully qualified table name for the tenant.
   * @param tableNameSuffix The part of the table name after the dot.
   * @return Returns the table name with a space appended to the end of the string.
   */
  protected String tableName(String tableNameSuffix) {
    return pool.getSchema() + "." + tableNameSuffix + " ";
  }
}
