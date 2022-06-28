package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;

import java.time.Instant;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

/**
 * The refresh token store provides persistence for refresh tokens. Refresh tokens need
 * to be persisted so that: 1) we can ensure they are redeemed only once, and 2) we can
 * take action (revoking all tokens for a user) when a given token is used more than once.
 * When a refresh token is attempted to be redeemed more than once we consider it leaked.
 */
public class RefreshTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(RefreshTokenStore.class);

  private static final String REFRESH_TOKEN_SUFFIX = "refresh_tokens";

  /**
   * Constructs the refresh token store.
   * @param vertx A reference to the current vertx object.
   * @param tenant The tenant which is in scope for a given token. This can be obtained
   * from the refresh token when the refresh token is created or arrives.
   */
  public RefreshTokenStore(Vertx vertx, String tenant) {
    super(vertx, tenant);
  }

  /**
   * Creates the table for this token store if it doesn't yet exist.
   * @return A failed future should the save operation fail. Otherwise a succeeded future
   * is returned, even if the table exists.
   */
  public Future<Void> createTableIfNotExists() {
    log.info("Creating tables and indexes for {} unless they already exist",
      RefreshTokenStore.class.getName());

      // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, expires_at INT8 NOT NULL)";

    String createIndexExpiresAt = "CREATE INDEX IF NOT EXISTS expires_at_idx ON " +
        tableName(REFRESH_TOKEN_SUFFIX) + "(expires_at)";
    String createIndexUserId = "CREATE INDEX IF NOT EXISTS user_id_idx ON " +
        tableName(REFRESH_TOKEN_SUFFIX) + "(user_id)";

    return pool.query(createTable).execute()
      .compose(x -> pool.query(createIndexExpiresAt).execute())
      .compose(x -> pool.query(createIndexUserId).execute())
      .mapEmpty();
  }

  /**
   * Save the token to the token store. This should be done anytime a new refresh token
   * is issued. Also cleans up any expired tokens in the background when called.
   * @param refreshToken The refresh token to store.
   * @return The completion of the save.
   */
  public Future<Void> saveToken(RefreshToken refreshToken) {
    return saveToken(refreshToken, false);
  }

  /**
   * Save the token to the token store. This should be done anytime a new refresh token
   * is issued. Also cleans up any expired tokens when called.
   * @param refreshToken The refresh token to store.
   * @param waitForCleanupExpired True if the returned Future completes when the cleanup completes,
   * false if it completes when the save completes.
   * @return The completion of the save, or the completion of both the save and the cleanup if
   * waitForCleanupExpired is true.
   */
  public Future<Void> saveToken(RefreshToken refreshToken, boolean waitForCleanupExpired) {
    UUID id = refreshToken.getId();
    UUID userId = refreshToken.getUserId();
    long expiresAt = refreshToken.getExpiresAt();
    boolean isRevoked = false;

    log.debug("Inserting token id {} into {} token store: {}", id, REFRESH_TOKEN_SUFFIX, expiresAt);

    String insert = "INSERT INTO " + tableName(REFRESH_TOKEN_SUFFIX) +
        "(id, user_id, is_revoked, expires_at) VALUES ($1, $2, $3, $4)";
    var values = Tuple.of(id, userId, isRevoked, expiresAt);

    if (waitForCleanupExpired) {
      // Insert the token in the database, and cleanup any expired tokens from storage, but
      // wait on the result of the cleanup.
      return pool.preparedQuery(insert).execute(values)
        .compose(x -> cleanupExpiredTokens()).mapEmpty();
    }

    // Insert the token in the database, and cleanup any expired tokens from storage, but
    // without waiting on the result.
    return pool.preparedQuery(insert).execute(values)
      .onComplete(x -> cleanupExpiredTokens()).mapEmpty();
  }

  /**
   * Check that the token has not been revoked. This will return a failed future if
   * the token has been redeemed. A refresh token which doesn't exist in storage is treated
   * as revoked.
   *
   * @param refreshToken The RefreshToken to check.
   * @return A failed future if the token has been revoked. Otherwise a succeeded future
   * with the token is returned.
   */
  public Future<Void> checkTokenNotRevoked(RefreshToken refreshToken) {
    UUID tokenId = refreshToken.getId();
    UUID userId = refreshToken.getUserId();
    String table = tableName(REFRESH_TOKEN_SUFFIX);

    // It could have expired so first check that. If it has there is no need to do anything
    // else. Note that the token is signed so it can't have reached this point unless it
    // hasn't been tampered with.
    if (tokenHasExpired(refreshToken)) {
      var e = new TokenValidationException("Token has expired. Considered revoked.", 401);
      return Future.failedFuture(e);
    }

    // Next check the token against the database.
    log.debug("Checking token redeemed of token id {}", tokenId);

    // Attempt to update the token to be revoked. If this update succeeds, the token
    // will now be marked as revoked, and a single row will be returned. If no rows
    // are returned, the update didn't succeed. This token has redeemed before
    // and is therefore revoked.
    String sql = "UPDATE " + table + "SET is_revoked=TRUE WHERE id=$1 AND is_revoked=FALSE";
    Tuple params = Tuple.of(tokenId);

    return pool.withConnection(conn -> {
      return conn.preparedQuery(sql).execute(params).compose(rows -> {

        // If the update has succeeded the row count will be 1. This means that the token
        // was never redeemed. The update however has now made it revoked
        // in an atomic operation. We can return success.
        if (rows.rowCount() == 1) {
          log.debug("Token {} has not yet been used, but is now revoked because it has been",
            tokenId);
          return Future.succeededFuture();
        }

        // The row count is not 1 so the token has been used more than once, has been
        // revoked when another token has been used more than once, or does not exist at all
        // either because it has been removed in cleaning up expired tokens or never existed in
        // the first place.
        String leakedMessage = "Refresh token {} is considered revoked." +
          " Revoking all tokens for user {}.";
        log.info(leakedMessage, tokenId, userId);

        return revokeAllTokensForUser(conn, userId)
          .compose(x -> {
             var msg = "Token leaked, does not exist or no longer exists." +
                 " All tokens for user are now revoked.";
             var e = new TokenValidationException(msg, 401);
             return Future.failedFuture(e);
         });
      });
    });
  }

  private boolean tokenHasExpired(RefreshToken rt) {
    return Instant.now().getEpochSecond() >= rt.getExpiresAt();
  }

  private Future<Void> revokeAllTokensForUser(SqlConnection conn, UUID userId) {
    log.debug("Revoking all refresh tokens for user id {}", userId);

    // First attempt to update but skipping any locks to be the most aggressive as we can.
    String updateSkipLocked = "UPDATE " + tableName(REFRESH_TOKEN_SUFFIX) +
      "SET is_revoked=TRUE " +
      "WHERE id IN (SELECT id FROM " + tableName(REFRESH_TOKEN_SUFFIX) +
                   "WHERE user_id=$1 AND is_revoked=FALSE " +
                   "FOR UPDATE SKIP LOCKED)";

     // Next come back and wait on any that were locked since we can't neglect them.
     String updateAll = "UPDATE " + tableName(REFRESH_TOKEN_SUFFIX) +
       "SET is_revoked=TRUE " +
       "WHERE user_id=$1 AND is_revoked=FALSE";

    Tuple params = Tuple.of(userId);

    return conn.preparedQuery(updateSkipLocked).execute(params)
      .compose(x -> conn.preparedQuery(updateAll).execute(params)).mapEmpty();
  }

  /**
   * Cleans up (deletes) refresh tokens which have passed their time of expiration.
   * Clients need to ensure that they are requesting new refresh tokens before they
   * expire.
   */
  public Future<Void> cleanupExpiredTokens() {
    long now = Instant.now().getEpochSecond();
    log.debug("Cleaning up tokens which are older than: {}", now);

    // Skips rows that are locked and therefore doesn't wait until they are unlocked.
    // Locks rows to be deleted and therefore avoids rollbacks.
    String delete = "DELETE FROM " + tableName(REFRESH_TOKEN_SUFFIX) +
      " WHERE id IN (SELECT id FROM " + tableName(REFRESH_TOKEN_SUFFIX) +
      " WHERE expires_at<$1 FOR UPDATE SKIP LOCKED)";
    Tuple params = Tuple.of(now);

    return pool.preparedQuery(delete).execute(params).mapEmpty();
  }

  public Future<Integer> countTokensStored(String tenant) {
    String select = "SELECT count(*) FROM " + tableName(REFRESH_TOKEN_SUFFIX);
    return getRows(select).map(rows -> rows.iterator().next().getInteger(0));
  }

  public Future<Void> removeAll() {
    return removeAll(REFRESH_TOKEN_SUFFIX);
  }

  /**
   * Revokes a single refresh token.
   * @param refreshToken The refresh token to revoke.
   * @return A failed future if the revoke operation failed. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> revokeToken(RefreshToken refreshToken) {
    UUID tokenId = refreshToken.getId();
    log.info("Revoking API token {}", tokenId);

    String sql = "UPDATE " + tableName(REFRESH_TOKEN_SUFFIX) +
        "SET is_revoked=TRUE WHERE id=$1";

    return pool.preparedQuery(sql).execute(Tuple.of(tokenId)).mapEmpty();
  }
}
