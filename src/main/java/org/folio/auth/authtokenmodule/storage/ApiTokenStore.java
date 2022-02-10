package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.ApiToken;

import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Tuple;

/**
 * The API token store provides persistence for API tokens. API tokens need to be
 * persisted so that they can be revoked.
 */
public class ApiTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(ApiTokenStore.class);

  private static String API_TOKEN_SUFFIX = "api_tokens";
  private TokenCreator tokenCreator;

  /**
   * Constructs the store for the given tenant. The tenant can be obtained from
   * the token when it arrives for validation or when it is created.
   * @param vertx A reference to the current vertx object.
   * @param tenant The tenant which is in scope for a given token. The tenant
   * can be obtained from the token when it arrives for validation or when it is
   * created.
   * @param tokenCreator A reference to the the current TokenCreator object
   * in scope for the main verticle.
   */
  public ApiTokenStore(Vertx vertx, String tenant, TokenCreator tokenCreator) {
    super(vertx, tenant);
    this.tokenCreator = tokenCreator;
  }

  /**
   * Creates the table for this token store if it doesn't yet exist.
   * @return A failed future should the save operation fail. Otherwise a
   * succeeded future is returned, even if the table exists.
   */
  public Future<Void> createIfNotExists() {
    // API tokens don't have an owning user. They are associated with a tenant
    // only. The token itself is persisted since it will need to be viewed by
    // end-users who have permission to see api tokens.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, API_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, token TEXT NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", TokenStore.class.getName());

    return pool.withConnection(conn -> {
      return conn.query(createTable).execute().mapEmpty();
    });
  }

  /**
   * Save the token to the token store. This should be done anytime a new API token is
   * issued.
   * @param conn An SqlConnection object to be used by the method to access the token
   * store. It is the responsibility of callers to close this connection.
   * @param apiToken The API token to store.
   * @return A failed future should the save operation fail. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> saveToken(ApiToken apiToken) {
    UUID id = apiToken.getId();
    long issuedAt = apiToken.getIssuedAt();
    boolean isRevoked = false;
    String tenant = apiToken.getTenant();

    String token = "";
    try {
      token = apiToken.encodeAsJWT(tokenCreator);
    } catch (Exception e) {
      log.error("Unable to encode token when saving: {}", e.getMessage());
      return Future.failedFuture("Unable to encode token when saving: " + e.getMessage());
    }

    log.info("Inserting token id {} into {} token store", id, API_TOKEN_SUFFIX);

    String insert = "INSERT INTO " + tableName(tenant, API_TOKEN_SUFFIX) +
        "(id, token, is_revoked, issued_at) VALUES ($1, $2, $3, $4)";
    var values = Tuple.of(id, token, isRevoked, issuedAt);

    return pool.withConnection(conn -> {
      return conn.preparedQuery(insert).execute(values).mapEmpty();
    });

    // TODO Should we return the encoded API token to callers?
  }

  /**
   * Check that the token has not been revoked. This will return a failed future if
   * the token has been revoked, otherwise it will return a succeeded future.
   * @param refreshToken The API token to check.
   * @return A failed future if the token has been revoked. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> checkTokenNotRevoked(ApiToken apiToken) {
    UUID tokenId = apiToken.getId();

    log.info("Checking revoked status of {} api token id {}",
      API_TOKEN_SUFFIX, tokenId);

    String select = "SELECT is_revoked FROM " + tableName(tenant, API_TOKEN_SUFFIX) +
      "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return pool.withConnection(conn -> {
      return getRow(conn, select, where).compose(row -> {
        Boolean isRevoked = row.getBoolean("is_revoked");

        log.info("Revoked status of {} token id {} is {}",
          API_TOKEN_SUFFIX, tokenId, isRevoked);

        if (!isRevoked) {
            return Future.succeededFuture();
        }
        return Future.failedFuture("API token revoked");
      });
    });
  }

  /**
   * Revokes the API token.
   * @param apiToken The API token to revoke.
   * @return A failed future if the revoke operation failed. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> revokeToken(ApiToken apiToken) {
    UUID tokenId = apiToken.getId();
    log.info("Revoking API token {}", tokenId);

    String update = "UPDATE " + tableName(tenant, API_TOKEN_SUFFIX) +
        "SET is_revoked=$1 WHERE id=$2";
    Tuple where = Tuple.of(Boolean.TRUE, tokenId);

    return pool.withConnection(conn -> {
      return conn.preparedQuery(update).execute(where).mapEmpty();
    });
  }

  // TODO Implement.
  public Future<List<ApiToken>> getApiTokensForTenant(String tenant) {
    throw new NotImplementedException("TODO");
  }
}
