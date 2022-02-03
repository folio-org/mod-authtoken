package org.folio.auth.authtokenmodule;

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

import org.folio.tlib.postgres.TenantPgPool;

public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  private static String REFRESH_TOKEN_SUFFIX = "refresh_tokens";
  private static String API_TOKEN_SUFFIX = "api_tokens";
  private Vertx vertx;
  private TokenCreator tokenCreator;

  public TokenStore(Vertx vertx, TokenCreator tokenCreator) {
    this.vertx = vertx;
    this.tokenCreator = tokenCreator;

    // TODO implement this to clean up expired tokens from the store.
    // vertx.setPeriodic(delay, handler)
  }

  public Future<Void> createIfNotExists(Vertx vertx, String tenant) {
    // Refresh tokens have an owning user, but the token itself isn't persisted
    // since it isn't used for anything. Just the id is enough.
    String createRefreshTokenTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, user_id UUID NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    // API tokens don't have an owning user. They are associated with a tenant
    // only. The token itself is persisted since it will need to be viewed by
    // end-users who have permission to see api tokens.
    String createApiTokenTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, API_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, token TEXT NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", TokenStore.class.getName());

    Future<Void> future = withPool(tenant, pool -> pool.query(createRefreshTokenTable).execute()).mapEmpty();
    return future.compose(x -> {
      return withPool(tenant, pool -> pool.query(createApiTokenTable).execute()).mapEmpty();
    });
  }

  public Future<Void> saveToken(RefreshToken rt) {
    UUID id = rt.getId();
    UUID userId = rt.getUserId();
    long issuedAt = rt.getIssuedAt();
    boolean isRevoked = false;
    String tenant = rt.getTenant();

    log.info("Inserting token id {} into {} token store", id, REFRESH_TOKEN_SUFFIX);

    String insert = "INSERT INTO " + tableName(tenant, REFRESH_TOKEN_SUFFIX) +
        "(id, user_id, is_revoked, issued_at) VALUES ($1, $2, $3, $4)";
    var values = Tuple.of(id, userId, isRevoked, issuedAt);

    return withPool(tenant, pool -> pool.preparedQuery(insert).execute(values)).mapEmpty();
  }

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

    return withPool(tenant, pool -> pool.preparedQuery(insert).execute(values)).mapEmpty();
  }

  public Future<Void> setTokenRevoked(Token t) {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  public Future<List<Token>> getTokensManagedByUser(String userId, String tenant) {
    throw new NotImplementedException("TODO");
  }

  public Future<Void> checkTokenNotRevoked(ApiToken apiToken) {
    return checkTokenNotRevoked(apiToken.getTenant(), apiToken.getId(), API_TOKEN_SUFFIX);
  }

  public Future<Void> checkTokenNotRevoked(RefreshToken rt) {
    return checkTokenNotRevoked(rt.getTenant(), rt.getId(), REFRESH_TOKEN_SUFFIX);
  }

  private Future<Void> checkTokenNotRevoked(String tenant, UUID tokenId, String tableNameSuffix) {
    log.info("Checking revoked status of {} token id {}", tableNameSuffix, tokenId);

    String select = "SELECT is_revoked FROM " + tableName(tenant, tableNameSuffix) + "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return withPool(tenant, pool -> pool.preparedQuery(select).execute(where)).compose(rows -> {
      if (rows.rowCount() == 0) {
        String msg = "Token with id {} not found in {} token store. Token is treated as revoked.";
        log.error(msg, tokenId, tableNameSuffix);
        return Future.failedFuture("Token not found");
      }
      Row row = rows.iterator().next();
      Boolean isRevoked = row.getBoolean("is_revoked");

      log.info("Revoked status of {} token id {} is {}", tableNameSuffix, tokenId, isRevoked);

      if (!isRevoked) {
        return Future.succeededFuture();
      }
      return Future.failedFuture("Token is revoked");
    });
  }

  // TODO This is not all token types. Only RTs.
  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  private String tableName(String tenant, String tableName) {
    return getSchema(tenant) + "." + tableName + " ";
  }

  // NOTE: TenantPgPool exposes a method for this, but that makes using the
  // withPool method
  // impossible since if we use TenantPgPool.getSchema the pool needs to be
  // constructed
  // prior to calling apply using the mapper.
  private String getSchema(String tenant) {
    return tenant + "_mod_authtoken";
  }

  private <T> Future<T> withPool(String tenant, Function<TenantPgPool, Future<T>> mapper) {
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    Future<T> future = mapper.apply(pool);
    return future.eventually(x -> pool.close());
  }
}
