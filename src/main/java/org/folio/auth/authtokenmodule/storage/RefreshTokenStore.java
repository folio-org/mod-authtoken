package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.netty.util.concurrent.SucceededFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

public class RefreshTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(RefreshTokenStore.class);

  private static String REFRESH_TOKEN_SUFFIX = "refresh_tokens";

  public RefreshTokenStore(Vertx vertx, String tenant) {
    super(vertx, tenant);

    // TODO implement this to clean up expired tokens from the store.
    // vertx.setPeriodic(delay, handler)
  }

  public Future<Void> createIfNotExists(SqlConnection conn) {
    // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, is_redeemed BOOLEAN NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", RefreshTokenStore.class.getName());

    return conn.query(createTable).execute().mapEmpty();
  }

  public Future<Void> saveToken(SqlConnection conn, RefreshToken rt) {
    UUID id = rt.getId();
    UUID userId = rt.getUserId();
    long issuedAt = rt.getIssuedAt();
    String tenant = rt.getTenant();
    boolean isRevoked = false;
    boolean isRedeemed = false;

    log.info("Inserting token id {} into {} token store", id, REFRESH_TOKEN_SUFFIX);

    String insert = "INSERT INTO " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id, user_id, is_revoked, is_redeemed, issued_at) VALUES ($1, $2, $3, $4, $5)";
    var values = Tuple.of(id, userId, isRevoked, isRedeemed, issuedAt);

    return conn.preparedQuery(insert).execute(values).mapEmpty();
  }

  public Future<Void> checkTokenNotRevoked(SqlConnection conn, RefreshToken rt) {
    // This is what this method does:
    // 1. Get is_redeemed for token. If token not found treat as revoked.
    // 2. If is_redeemed is false, call setTokenRedeemed, then checkTokenNotRevoked since it
    //    could have been revoked by another client or party attempting to redeem a different
    //    one or it. It doesn't matter.
    // 3. If it is_redeemed true call revokeAllTokensForUser and return a failed future.
    //    This is the second use of the token and it means the token has been leaked. We
    //    consider the user's account compromised and revoke all their refresh tokens.
    UUID tokenId = rt.getId();
    UUID userId = rt.getId();
    String table = tableName(tenant, REFRESH_TOKEN_SUFFIX);

    log.info("Checking token redeemed of token id {} for tenant {}", tokenId, tenant);

    String select = "SELECT is_redeemed FROM " + table + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return getRow(conn, select, where).compose(row -> {
      Boolean isRedeemed = row.getBoolean("is_redeemed");

      log.info("Redeemed status of {} token id {} is {}", REFRESH_TOKEN_SUFFIX, tokenId, isRedeemed);

      if (!isRedeemed) {
        // Token has not been used more than once. Set it as redeemed so it can't be used again.
        return setTokenRedeemed(conn, rt).compose(x -> {
          return checkTokenNotRevoked(conn, tokenId, REFRESH_TOKEN_SUFFIX);
        });
      }

      // Token has been used more than once since isRedeemed is true.
      String leakedMessage = "Refresh token {} attempted to be used twice." +
      " It is considered leaked. Revoking all tokens for user {}.";
      log.info(leakedMessage, tokenId, userId);

      return revokeAllTokensForUser(conn, userId).compose(x -> {
        return Future.failedFuture("Token leaked");
      });
    });
  }

  private Future<Void> setTokenRedeemed(SqlConnection conn, RefreshToken rt) {
    UUID tokenId = rt.getId();
    String tenant = rt.getTenant();

    log.info("Setting refresh token id {} to redeemed", tokenId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_redeemed=true WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }

  private Future<Void> revokeAllTokensForUser(SqlConnection conn, UUID userId) {
    log.info("Setting all refresh tokens for user id {} to revoked", userId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_revoked=true WHERE user_id=$1";
    Tuple where = Tuple.of(userId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }

  // TODO This is not all token types. Only RTs.
  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }
}
