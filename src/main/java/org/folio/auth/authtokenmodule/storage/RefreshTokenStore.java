package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.time.Instant;
import java.util.UUID;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

public class RefreshTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(RefreshTokenStore.class);

  private static String REFRESH_TOKEN_SUFFIX = "refresh_tokens";

  public RefreshTokenStore(Vertx vertx, String tenant) {
    super(vertx, tenant);

    // TODO implement this to clean up expired tokens from the store.
    // TODO Consider using an okapi timer.
    // vertx.setPeriodic(delay, handler)
  }

  public Future<Void> createIfNotExists(SqlConnection conn) {
    // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, is_redeemed BOOLEAN NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, expires_at INT8 NOT NULL)";

    log.info("Creating {} tables", RefreshTokenStore.class.getName());

    return conn.query(createTable).execute().mapEmpty();
  }

  public Future<Void> saveToken(SqlConnection conn, RefreshToken rt) {
    UUID id = rt.getId();
    UUID userId = rt.getUserId();
    long expiresAt = rt.getExpiresAt();
    String tenant = rt.getTenant();
    boolean isRevoked = false;
    boolean isRedeemed = false;

    log.info("Inserting token id {} into {} token store: {}", id, REFRESH_TOKEN_SUFFIX, expiresAt);

    String insert = "INSERT INTO " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id, user_id, is_revoked, is_redeemed, expires_at) VALUES ($1, $2, $3, $4, $5)";
    var values = Tuple.of(id, userId, isRevoked, isRedeemed, expiresAt);

    return conn.preparedQuery(insert).execute(values).mapEmpty();
  }

  /**
   * Check that the token has not been revoked. This will return a failed future if
   * the token has been revoked, otherwise it will return a succeeded future.
   * @param conn An SqlConnection object to be used by the method to access the token
   * store.
   * @param rt The RefreshToken to check.
   * @return A failed future if the token has been revoked. Otherwise a succeeded future
   * is returned.
   */
  public Future<Void> checkTokenNotRevoked(SqlConnection conn, RefreshToken rt) {
    // This is what this method does:
    // 1. Get isRedeemed and isRevoked for token. If token not found treat as revoked.
    // 2. If it has been revoked, fail the future. We need to check this here since
    //    other requests could have revoked the token anytime. We can't let these through.
    // 3. If isRedeemed is false, call setTokenRedeemed and return a success. It is not
    //    revoked or redeemed. This is the desired state. RTs can be used only once.
    //    Any subsequent uses must be considered as a leaked (compromised) token.
    // 4. If isRedeemed is true call revokeAllTokensForUser and return a failed future.
    //    isRedeemed true means "someone tried to use it a second time". This is the
    //    second use of the token and it means the token has been leaked. We
    //    consider the user's account compromised and revoke all their refresh tokens.
    //    They will need to login again to get a new RefreshToken that isn't revoked
    //    or redeemed.
    UUID tokenId = rt.getId();
    UUID userId = rt.getUserId();
    String table = tableName(tenant, REFRESH_TOKEN_SUFFIX);

    log.info("Checking token redeemed of token id {} for tenant {}", tokenId, tenant);

    String select = "SELECT is_redeemed, is_revoked FROM " + table + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

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
        return setTokenRedeemed(conn, rt);
      }

      // isRedeemed is true so the token has been used more than once. Revoke
      // all tokens for the user.
      String leakedMessage = "Refresh token {} attempted to be used twice." +
      " It is considered leaked. Revoking all tokens for user {}.";
      log.info(leakedMessage, tokenId, userId);

      return revokeAllTokensForUser(conn, userId).compose(x -> {
        return Future.failedFuture("Token leaked. Revoked all tokens for user.");
      });
    });
  }

  private Future<Void> setTokenRedeemed(SqlConnection conn, RefreshToken rt) {
    UUID tokenId = rt.getId();
    String tenant = rt.getTenant();

    log.info("Setting refresh token id {} to redeemed", tokenId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_redeemed=$1 WHERE id=$2";
    Tuple where = Tuple.of(Boolean.TRUE, tokenId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }

  private Future<Void> revokeAllTokensForUser(SqlConnection conn, UUID userId) {
    log.info("Revoking all refresh tokens for user id {}", userId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_revoked=$1 WHERE user_id=$2";
    Tuple where = Tuple.of(Boolean.TRUE, userId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }

  public Future<Void> cleanupExpiredTokens(SqlConnection conn) {
    long now = Instant.now().getEpochSecond();
    log.info("Cleaning up tokens which are older than: {}", now);

    String delete = "DELETE FROM " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
      "WHERE expires_at<$1";
    Tuple where = Tuple.of(now);

    return conn.preparedQuery(delete).execute(where).mapEmpty();
  }

  public Future<Integer> countTokensStored(SqlConnection conn, String tenant) {
    String select = "SELECT * FROM " + tableName(tenant, REFRESH_TOKEN_SUFFIX);
    return getRows(conn, select).map(rows -> rows.rowCount());
  }

  public Future<Void> removeAll(SqlConnection conn) {
    return removeAll(conn, REFRESH_TOKEN_SUFFIX);
  }
}
