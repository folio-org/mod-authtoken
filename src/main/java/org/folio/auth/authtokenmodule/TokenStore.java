package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;

import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;

import org.apache.commons.lang3.NotImplementedException;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Tuple;

import org.folio.tlib.postgres.TenantPgPool;

public class TokenStore {

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

    String createType = "CREATE TYPE token_type AS ENUM ('refresh', 'api')";
    String createTable = "CREATE TABLE IF NOT EXISTS " + tableName(pool) +
        "(id UUID PRIMARY key, user_id UUID, token TEXT, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL, " +
        "type token_type NOT NULL)";

    // TODO This comes back as Illegal state exception result is already complete
    // Future<Void> future = pool.query(createType).execute().mapEmpty();
    // return future.compose(x -> pool.query(createTable).execute().mapEmpty());

    // This works.
    return pool.query(createTable).execute().mapEmpty();
  }

  public Future<Void> saveToken(RefreshToken t) throws JOSEException, ParseException {
    UUID id = UUID.fromString(t.getClaims().getString("jti"));
    UUID userId = UUID.fromString(t.getClaims().getString("user_id"));
    String tenant = t.getClaims().getString("tenant");
    long issuedAt = t.getClaims().getLong("iat");
    boolean isRevoked = false;

    // TODO Determine whether to try/catch here for the exeptions here or pass them along in throws.
    String token = t.encodeAsJWT(tokenCreator);

    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    String insert = "INSERT INTO " + tableName(pool) +
      "(id, user_id, token, is_revoked, issued_at) VALUES ($1, $2, $3, $4, $5)";
    var tuple = Tuple.of(id, userId, token, isRevoked, issuedAt);
    return pool.preparedQuery(insert).execute(tuple).mapEmpty();
  }

  public Future<Void> saveToken(ApiToken t) throws JOSEException {
    throw new  NotImplementedException("TODO");
  }

  public Future<Void> setTokenRevoked(Token t) {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  public Future<List<Token>> getTokensManagedByUser(String userId, String tenant) {
    throw new NotImplementedException("TODO");
  }

  public static Future<Void> checkTokenRevoked(Vertx v) {
    TenantPgPool pool = TenantPgPool.pool(v, "tokenstore-test-tenant");

    String select = "SELECT * FROM " + tableName(pool);
    //String select = "SELECT * FROM pg_database";
    return pool.query(select).execute().mapEmpty();
  }

  // TODO This is not all token types. Only RTs.
  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claim.
    throw new NotImplementedException("TODO");
  }

  private static String tableName(TenantPgPool pool) {
    return pool.getSchema() + ".tokenstore ";
  }
}
