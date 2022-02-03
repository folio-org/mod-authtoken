package org.folio.auth.authtokenmodule.storage;

import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.Token;

import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.NotImplementedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Tuple;

public class ApiTokenStore extends TokenStore {
  private static final Logger log = LogManager.getLogger(ApiTokenStore.class);

  private static String API_TOKEN_SUFFIX = "api_tokens";
  private TokenCreator tokenCreator;

  public ApiTokenStore(Vertx vertx, TokenCreator tokenCreator) {
    super(vertx);
    this.tokenCreator = tokenCreator;
  }

  public Future<Void> createIfNotExists(Vertx vertx, String tenant) {
    // API tokens don't have an owning user. They are associated with a tenant
    // only. The token itself is persisted since it will need to be viewed by
    // end-users who have permission to see api tokens.
    String createTable = "CREATE TABLE IF NOT EXISTS " +
        tableName(tenant, API_TOKEN_SUFFIX) +
        "(id UUID PRIMARY key, token TEXT NOT NULL, " +
        "is_revoked BOOLEAN NOT NULL, issued_at INT8 NOT NULL)";

    log.info("Creating {} tables", TokenStore.class.getName());

    return withPool(tenant, pool -> pool.query(createTable).execute()).mapEmpty();
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

    // TODO Should we return the encoded API token to callers?
    return withPool(tenant, pool -> pool.preparedQuery(insert).execute(values)).mapEmpty();
  }

  // TODO Add a property already_used to the refresh token store.

  public Future<Void> setTokenRevoked(ApiToken apiToken) {
    // Setting an ApiToken as revoked only revokes that token.
    throw new NotImplementedException("TODO");
  }

  public Future<List<Token>> getApiTokensForTenant(String tenant) {
    throw new NotImplementedException("TODO");
  }

  public Future<Void> checkTokenNotRevoked(ApiToken apiToken) {
    return checkTokenNotRevoked(apiToken.getTenant(), apiToken.getId(), API_TOKEN_SUFFIX);
  }
}
