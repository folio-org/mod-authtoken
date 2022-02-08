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
import io.vertx.sqlclient.SqlConnection;
import io.vertx.sqlclient.Tuple;

public class ApiTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(ApiTokenStore.class);

  private static String API_TOKEN_SUFFIX = "api_tokens";
  private TokenCreator tokenCreator;

  public ApiTokenStore(Vertx vertx, String tenant, TokenCreator tokenCreator) {
    super(vertx, tenant);
    this.tokenCreator = tokenCreator;
  }

  public Future<Void> createIfNotExists(SqlConnection conn) {
    // API tokens don't have an owning user. They are associated with a tenant
    // only. The token itself is persisted since it will need to be viewed by
    // end-users who have permission to see api tokens.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, API_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, token TEXT NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", TokenStore.class.getName());

    return conn.query(createTable).execute().mapEmpty();
  }

  public Future<Void> saveToken(SqlConnection conn, ApiToken apiToken) {
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

    // TODO Should we return the encoded API token to callers?
    return conn.preparedQuery(insert).execute(values).mapEmpty();
  }

  public Future<Void> checkTokenNotRevoked(SqlConnection conn, ApiToken apiToken) {
    UUID tokenId = apiToken.getId();

    log.info("Checking revoked status of {} api token id {}", API_TOKEN_SUFFIX, tokenId);

    String select = "SELECT is_revoked FROM " + tableName(tenant, API_TOKEN_SUFFIX) +
      "WHERE id=$1";
    Tuple where = Tuple.of(tokenId);

    return getRow(conn, select, where).compose(row -> {
      Boolean isRevoked = row.getBoolean("is_revoked");

      log.info("Revoked status of {} token id {} is {}", API_TOKEN_SUFFIX, tokenId, isRevoked);

      if (!isRevoked) {
        return Future.succeededFuture();
      }
      return Future.failedFuture("API token is revoked");
    });
  }

  public Future<Void> setTokenRevoked(SqlConnection conn, ApiToken apiToken) {
    UUID tokenId = apiToken.getId();
    log.info("Revoking API token {}", tokenId);

    String update = "UPDATE " + tableName(tenant, API_TOKEN_SUFFIX) +
        "SET is_revoked=$1 WHERE id=$2";
    Tuple where = Tuple.of(Boolean.TRUE, tokenId);

    return conn.preparedQuery(update).execute(where).mapEmpty();
  }

  public Future<List<ApiToken>> getApiTokensForTenant(SqlConnection conn, String tenant) {
    throw new NotImplementedException("TODO");
  }
}
