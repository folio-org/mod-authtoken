package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;

import java.text.ParseException;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

public class TokenStore {
  private static final Logger log = LogManager.getLogger(TokenStore.class);

  private Vertx vertx;
  private TokenCreator tokenCreator;

  public TokenStore(Vertx vertx, TokenCreator tokenCreator) {
    this.vertx = vertx;
    this.tokenCreator = tokenCreator;

    // TODO implement this to clean up expired tokens from the store.
    // vertx.setPeriodic(delay, handler)
  }

  public static Future<Void> createIfNotExists(Vertx vertx, String tenant) {
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);

    // String createType = "CREATE TYPE token_type AS ENUM ('refresh', 'api')";
    String createTable = "CREATE TABLE IF NOT EXISTS " + tableName(pool, "refresh") +
        "(id UUID PRIMARY key, user_id UUID, token TEXT, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    // TODO This comes back as Illegal state exception result is already complete
    // Future<Void> future = pool.query(createType).execute().mapEmpty();
    // return future.compose(x -> pool.query(createTable).execute().mapEmpty());

    // This works.
    return pool.query(createTable).execute().mapEmpty();
  }

  public Future<Void> saveToken(RefreshToken rt) throws JOSEException, ParseException {
    UUID id = rt.getId();
    UUID userId = UUID.fromString(rt.getClaims().getString("user_id"));
    String tenant = rt.getClaims().getString("tenant");
    long issuedAt = rt.getClaims().getLong("iat");
    boolean isRevoked = false;

    // TODO Determine whether to try/catch here for the exeptions here or pass them
    // along in throws.
    String token = rt.encodeAsJWT(tokenCreator);

    TenantPgPool pool = TenantPgPool.pool(vertx, rt.getTenant());
    String insert = "INSERT INTO " + tableName(pool, "refresh") +
        "(id, user_id, token, is_revoked, issued_at) VALUES ($1, $2, $3, $4, $5)";
    var tuple = Tuple.of(id, userId, token, isRevoked, issuedAt);
    return pool.preparedQuery(insert).execute(tuple).mapEmpty();

    // TODO This works, but doing the query with the pattern below in
    // checkTokenRevoked
    // does not. I'm not sure if this is the fix for pool being occasionally closed.
    // return withPool(tenant, pool -> {
    // String insert = "INSERT INTO " + tableName(pool, "refresh") +
    // "(id, user_id, token, is_revoked, issued_at) VALUES ($1, $2, $3, $4, $5)";
    // var tuple = Tuple.of(id, userId, token, isRevoked, issuedAt);

    // return pool.preparedQuery(insert).execute(tuple).mapEmpty();
    // });
  }

  public Future<Void> saveToken(ApiToken t) throws JOSEException {
    throw new NotImplementedException("TODO");
  }

  public Future<Void> setTokenRevoked(Token t) {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  public Future<List<Token>> getTokensManagedByUser(String userId, String tenant) {
    throw new NotImplementedException("TODO");
  }

  public void checkTokenRevoked(RefreshToken rt, Handler<Boolean> resultHandler) {
    log.info("calling checkTokenRevoked");
    TenantPgPool pool = TenantPgPool.pool(vertx, rt.getTenant());
    String select = "SELECT * FROM " + tableName(pool, "refresh") + "WHERE id='" + rt.getId() + "'";
    pool.query(select).execute(ar -> {
      if (ar.succeeded()) {
        log.info("Got rows {}", ar.result().rowCount());
        resultHandler.handle(false);
        return;
      }
      log.error("Error getting rows: {}", ar.cause().getMessage());
      resultHandler.handle(true);
    });
  }

  // TODO This is not all token types. Only RTs.
  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  private static String tableName(TenantPgPool pool, String tableName) {
    return pool.getSchema() + "." + tableName + " ";
  }

  /**
   * Create a TenantPgPool, run the mapper on it, close the pool,
   * and return the result from the mapper.
   */
  private <T> Future<T> withPool(String tenant, Function<TenantPgPool, Future<T>> mapper) {
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    Future<T> future = mapper.apply(pool);
    return future.eventually(x -> pool.close());
  }
}
