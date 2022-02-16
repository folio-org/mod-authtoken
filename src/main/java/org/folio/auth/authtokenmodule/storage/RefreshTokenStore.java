package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.tokens.RefreshToken;

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

    // TODO implement this to clean up expired tokens from the store.
    // TODO Consider using an okapi timer.
    // vertx.setPeriodic(delay, handler)
  }

  /**
   * Creates the table for this token store if it doesn't yet exist.
   * @return A failed future should the save operation fail. Otherwise a succeeded future
   * is returned, even if the table exists.
   */
  public Future<Void> createTableIfNotExists() {
    // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, is_redeemed BOOLEAN NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, expires_at INT8 NOT NULL)";

    log.info("Creating {} tables", RefreshTokenStore.class.getName());

    return pool.query(createTable).execute()
      .mapEmpty();
  }

  public Future<Void> createIndexesIfNotExists() {
    String createIndexExpiresAt = "CREATE INDEX IF NOT EXIST ON " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) + "(expires_at)";
    String createIndexUserId = "CREATE INDEX IF NOT EXIST ON " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) + "(user_id)";

    log.info("Creating {} tables", RefreshTokenStore.class.getName());

    return pool.query(createIndexExpiresAt).execute()
      .compose(x -> pool.query(createIndexUserId).execute())
      .mapEmpty();
  }

  /**
   * Save the token to the token store. This should be done anytime a new refresh token
   * is issued.
   * @param refreshToken The refresh token to store.
   * @return A failed future should the save operation fail. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> saveToken(RefreshToken refreshToken) {
    UUID id = refreshToken.getId();
    UUID userId = refreshToken.getUserId();
    long expiresAt = refreshToken.getExpiresAt();
    String tenant = refreshToken.getTenant();
    boolean isRevoked = false;
    boolean isRedeemed = false;

    log.info("Inserting token id {} into {} token store: {}", id, REFRESH_TOKEN_SUFFIX, expiresAt);

    String insert = "INSERT INTO " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id, user_id, is_revoked, is_redeemed, expires_at) VALUES ($1, $2, $3, $4, $5)";
    var values = Tuple.of(id, userId, isRevoked, isRedeemed, expiresAt);

    return pool.preparedQuery(insert).execute(values).mapEmpty();
  }

  /**
   * Check that the token has not been revoked. This will return a failed future if
   * the token has been revoked, otherwise it will return a succeeded future.
   *
   * This is what this method does:
   * 1. Get isRedeemed and isRevoked for token. If token not found treat as revoked.
   * 2. If it has been revoked, fail the future. We need to check this here since
   *    other requests could have revoked the token anytime. We can't let these through.
   * 3. If isRedeemed is false, call setTokenRedeemed and return a success. It is not
   *    revoked or redeemed. This is the desired state. RTs can be used only once.
   *    Any subsequent uses must be considered as a leaked (compromised) token.
   * 4. If isRedeemed is true call revokeAllTokensForUser and return a failed future.
   *    isRedeemed true means "someone tried to use it a second time". This is the
   *    second use of the token and it means the token has been leaked. We
   *    consider the user's account compromised and revoke all their refresh tokens.
   *    They will need to login again to get a new RefreshToken that isn't revoked
   *    or redeemed.
   *
   * @param refreshToken The RefreshToken to check.
   * @return A failed future if the token has been revoked. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> checkTokenNotRevoked(RefreshToken refreshToken) {
    UUID tokenId = refreshToken.getId();
    UUID userId = refreshToken.getUserId();
    String table = tableName(tenant, REFRESH_TOKEN_SUFFIX);

    log.info("Checking token redeemed of token id {} for tenant {}", tokenId, tenant);

    String select = "SELECT is_redeemed, is_revoked FROM " + table + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return pool.withConnection(conn -> {
      return getRow(conn, select, where).compose(row -> {
        Boolean isRedeemed = row.getBoolean("is_redeemed");
        Boolean isRevoked = row.getBoolean("is_revoked");

        log.info("Redeemed status of {} token id {} is {}", REFRESH_TOKEN_SUFFIX, tokenId, isRedeemed);
        log.info("Revoked status of {} token id {} is {}", REFRESH_TOKEN_SUFFIX, tokenId, isRevoked);

        // The token could have been revoked by a different request so we check that first.
        // If it has been revoked, all tokens should already have been revoked so we can safely
        // return.
        if (isRevoked) {
          log.info("Token {} has been revoked", tokenId);
          return Future.failedFuture("Token is revoked");
        }

        if (!isRedeemed) {
          // Token has not been used more than once. Set it as redeemed so it can't be used again
          // and return a success.
          log.info("Token {} has not yet been redeemed so it is not revoked", tokenId);
          return setTokenRedeemed(conn, refreshToken);
        }

        // isRedeemed is true so the token has been used more than once. Revoke
        // all tokens for the user.
        String leakedMessage = "Refresh token {} attempted to be used twice." +
        " It is considered leaked. Revoking all tokens for user {}.";
        log.info(leakedMessage, tokenId, userId);

        return revokeAllTokensForUser(conn, userId).compose(y -> {
          return Future.failedFuture("Token leaked. Revoked all tokens for user.");
        });
      });
    });
  }

  /**
   * Cleans up (deletes) refresh tokens which have passed their time of expiration.
   * Clients need to ensure that they are requesting new refresh tokens before they
   * expire.
   * @return A failed future should the deletion fail. A succeeded future if the
   * deletion succeeds.
   */
  public Future<Void> cleanupExpiredTokens() {
    long now = Instant.now().getEpochSecond();
    log.info("Cleaning up tokens which are older than: {}", now);

    // Skips rows that are locked and therefore doesn't wait until they are unlocked.
    // Locks rows to be deleted and therefore avoids rollbacks.
    String delete = "DELETE FROM " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
      " WHERE id IN (SELECT id FROM " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
      " WHERE expires_at<$1 FOR UPDATE SKIP LOCKED)";
    Tuple where = Tuple.of(now);

    return pool.preparedQuery(delete).execute(where).mapEmpty();
  }

  public Future<Integer> countTokensStored(String tenant) {
    String select = "SELECT count(*) FROM " + tableName(tenant, REFRESH_TOKEN_SUFFIX);
    return getRows(select).map(rows -> rows.iterator().next().getInteger(0));
  }

  public Future<Void> removeAll() {
    return removeAll(REFRESH_TOKEN_SUFFIX);
  }

  private Future<Void> setTokenRedeemed(SqlConnection conn, RefreshToken refreshToken) {
    UUID tokenId = refreshToken.getId();
    String tenant = refreshToken.getTenant();

    log.info("Setting refresh token id {} to redeemed", tokenId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_redeemed=TRUE WHERE id=$1";

    return conn.preparedQuery(update).execute(Tuple.of(tokenId)).mapEmpty();
  }

  private Future<Void> revokeAllTokensForUser(SqlConnection conn, UUID userId) {
    log.info("Revoking all refresh tokens for user id {}", userId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_revoked=$1 WHERE user_id=$2";
    Tuple where = Tuple.of(Boolean.TRUE, userId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }
}
