package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.UUID;

public class RefreshToken extends Token {

  // TODO This could be obtained from the env.
  int expirationSeconds = 60 * 60 * 24;

  public RefreshToken(String tenant, String username, String userId, String address) {
    long now = Instant.now().getEpochSecond();
    claims = new JsonObject()
    .put("type", TokenType.REFRESH)
    .put("exp", now + expirationSeconds)
    .put("iat", now)
    .put("sub", username)
    .put("user_id", userId)
    .put("tenant", tenant)
    .put("address", address)
    .put("jti", UUID.randomUUID().toString())
    .put("prn", "refresh");
  }

  public RefreshToken(String sourceJwt) {
    source = sourceJwt;
    claims = getClaims(sourceJwt);
  }

  public Future<Token> validate(MultiMap headers) {
    try { 
      validateCommon(headers);
    } catch (Exception e) {
      return Future.failedFuture(e);
    }

    // TODO Check the exp claim.
    // TODO Validate the RT against the stored token.

    return Future.succeededFuture(this);
  }

}
