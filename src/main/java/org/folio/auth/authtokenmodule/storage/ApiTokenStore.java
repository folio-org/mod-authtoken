package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;

/**
 * The API token store provides persistence for API tokens. API tokens need to be
 * persisted so that they can be revoked.
 */
public class ApiTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(ApiTokenStore.class);

  private static final String API_TOKEN_SUFFIX = "api_tokens";
  private final TokenCreator tokenCreator;

  /**
   * Constructs the store for the given tenant. The tenant can be obtained from
   * the token when it arrives for validation or when it is created.
   * @param vertx A reference to the current vertx object.
   * @param tenant The tenant which is in scope for a given token. The tenant
   * can be obtained from the token when it arrives for validation or when it is
   * created.
   * @param tokenCreator A reference to the current TokenCreator object
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
  public Future<Void> createTableIfNotExists() {
    log.info("Creating tables for {} unless they already exist", ApiTokenStore.class.getName());

    // API tokens don't have an owning user. They are associated with a tenant
    // only. The token itself is persisted since it will need to be viewed by
    // end-users who have permission to see api tokens.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(API_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, token TEXT NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    return pool.query(createTable).execute().mapEmpty();
  }

  /**
   * Save the token to the token store. This should be done anytime a new API token is
   * issued.
   * @param apiToken The API token to store.
   * @return A failed future should the save operation fail. Otherwise a succeeded future
   * is returned. If the future succeeds, a string representation of the token is returned.
   */
  public Future<String> saveToken(ApiToken apiToken) {
    UUID id = apiToken.getId();
    long issuedAt = apiToken.getIssuedAt();
    boolean isRevoked = false;

    String token;
    try {
      token = apiToken.encodeAsJWT(tokenCreator);
    } catch (Exception e) {
      log.error("Unable to encode token when saving: {}", e.getMessage());
      var responseException =
          new TokenValidationException("Unable to encode token when saving: " + e.getMessage(), 500);
      return Future.failedFuture(responseException);
    }

    log.debug("Inserting token id {} into {} token store", id, API_TOKEN_SUFFIX);

    String sql = "INSERT INTO " + tableName(API_TOKEN_SUFFIX) +
        "(id, token, is_revoked, issued_at) VALUES ($1, $2, $3, $4)";
    Tuple params = Tuple.of(id, token, isRevoked, issuedAt);

    return pool.preparedQuery(sql).execute(params).map(token);
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

    log.debug("Checking revoked status of {} api token id {}", API_TOKEN_SUFFIX, tokenId);

    String sql = "SELECT is_revoked FROM " + tableName(API_TOKEN_SUFFIX) +
      "WHERE id=$1";
    Tuple params = Tuple.of(tokenId);

    return getRow(sql, params).compose(row -> {
      Boolean isRevoked = row.getBoolean("is_revoked");

      log.debug("Revoked status of {} token id {} is {}", API_TOKEN_SUFFIX, tokenId, isRevoked);

      if (!isRevoked) {
          return Future.succeededFuture();
      }
      return Future.failedFuture(new TokenValidationException("API token revoked", 401));
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

    String sql = "UPDATE " + tableName(API_TOKEN_SUFFIX) +
        "SET is_revoked=TRUE WHERE id=$1";

    return pool.preparedQuery(sql).execute(Tuple.of(tokenId)).mapEmpty();
  }

  /**
   * Get all of the API tokens for a given tenant. No permissions check is made. This is the
   * responsibility of callers.
   * @param tenant The tenant for the API tokens.
   * @return Returns a list of API tokens, each in their string representation.
   */
  public Future<List<String>> getApiTokensForTenant(String tenant) {
    String select = "SELECT token FROM " + tableName(API_TOKEN_SUFFIX);
    List<String> tokens = new ArrayList<>();
    return pool.query(select).execute().compose(rows -> {
      for (Row row : rows) {
        String tokenString = row.getString("token");
        tokens.add(tokenString);
      }
      log.debug("Retrieved {} token rows for tenant {}", rows.rowCount(), tenant);
      return Future.succeededFuture(tokens);
    });
  }

  public Future<Void> removeAll() {
    return removeAll(API_TOKEN_SUFFIX);
  }
}
