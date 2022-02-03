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

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.Tuple;

public class RefreshTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(RefreshTokenStore.class);

  private static String REFRESH_TOKEN_SUFFIX = "refresh_tokens";

  public RefreshTokenStore(Vertx vertx) {
    super(vertx);

    // TODO implement this to clean up expired tokens from the store.
    // vertx.setPeriodic(delay, handler)
  }

  public Future<Void> createIfNotExists(Vertx vertx, String tenant) {
    // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, is_redeemed BOOLEAN NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", TokenStore.class.getName());

    return withPool(tenant, pool -> pool.query(createTable).execute()).mapEmpty();
  }

  public Future<Void> saveToken(RefreshToken rt) {
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

    return withPool(tenant, pool -> pool.preparedQuery(insert).execute(values)).mapEmpty();
  }

  public Future<Void> checkTokenNotRevoked(RefreshToken rt) {
    // Get redeemed for token
    // If redeemed is false, setTokenRedeemed, checkTokenNotRevoked
    // Else setAllRefreshTokensRevokedForUser and return failedFuture

    return checkTokenNotRevoked(rt.getTenant(), rt.getId(), REFRESH_TOKEN_SUFFIX);
  }

  private Future<Void> checkTokenNotRedeemed(RefreshToken rt) {
    UUID tokenId = rt.getId();
    String tenant = rt.getTenant();
    String table = tableName(tenant, REFRESH_TOKEN_SUFFIX);

    log.info("Checking token redeemed of token id {} for tenant {}", tokenId, tenant);

    String select = "SELECT is_redeemed FROM " + table + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return withPool(tenant, pool -> pool.preparedQuery(select).execute(where)).compose(rows -> {
      if (rows.rowCount() == 0) {
        String msg = "Token with id {} not found in {} token store. Token is treated as redeemed.";
        log.error(msg, tokenId, REFRESH_TOKEN_SUFFIX);
        return Future.failedFuture("Token not found, treated as redeemed");
      }
      Row row = rows.iterator().next();
      Boolean isRedeemed = row.getBoolean("is_redeemed");

      log.info("Redeemed status of {} token id {} is {}", REFRESH_TOKEN_SUFFIX, tokenId, isRedeemed);

      if (!isRedeemed) {
        return Future.succeededFuture();
      }
      return Future.failedFuture("Token has already been redeemed");
    });
  }

  private Future<Void> setTokenRedeemed(RefreshToken rt) {
    UUID tokenId = rt.getId();
    String tenant = rt.getTenant();

    log.info("Setting refresh token id {} to redeemed", tokenId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_redeemed=true WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return withPool(tenant, pool -> pool.preparedQuery(update).execute(where)).mapEmpty();
  }

  private Future<Void> setAllRevokedForUser(String tenant, String userId) {
    log.info("Setting all refresh tokens for user id {} to revoked", userId);

    String update = "UPDATE " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "SET is_revoked=true WHERE user_id=$1";
    Tuple where = Tuple.of(userId);

    return withPool(tenant, pool -> pool.preparedQuery(update).execute(where)).mapEmpty();
  }

  // TODO This is not all token types. Only RTs.
  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }
}
