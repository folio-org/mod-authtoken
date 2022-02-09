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
 * The base class for all token storage.
 */
public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  protected Vertx vertx;
  protected String tenant;
  protected TenantPgPool pool;

  public TokenStore(Vertx vertx, String tenant) {
    this.vertx = vertx;
    this.tenant = tenant;
  }

  /**
   * Obtain a sql connection to the store. It is the responsibility of callers to
   * close this connection.
   * @return A succeeded future wrapping the SqlConnection object which can be used for
   * subsequent operations in the store, or a failed future if the connection fails.
   */
  public Future<SqlConnection> connect() {
    pool = TenantPgPool.pool(vertx, tenant);
    return pool.getConnection();
  }

  /**
   * Removes all tokens from storage for the tenant associated with this instance
   * of the token store.
   * @param conn An SqlConnection object to be used by the method to access the token
   * store. It is the responsibility of callers to close this connection.
   * @param suffix The string appended to the end of the table name which identifies
   * the table.
   * @return A succeeded future should the operation succeed, otherwise a failed
   * future.
   */
  public Future<Void> removeAll(SqlConnection conn, String suffix) {
    log.info("Removing all tokens from storage");

    String delete = "DELETE FROM " + tableName(tenant, suffix);

    return conn.preparedQuery(delete).execute().mapEmpty();
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

  protected Future<RowSet<Row>> getRows(SqlConnection conn, String select, Tuple where) {
    return conn.preparedQuery(select).execute(where).map(rows -> rows);
  }

  protected Future<RowSet<Row>> getRows(SqlConnection conn, String select) {
    return conn.preparedQuery(select).execute().map(rows -> rows);
  }

  protected String tableName(String tenant, String tableName) {
    return pool.getSchema() + "." + tableName + " ";
  }
}
