package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.time.Instant;

public class RefreshToken extends Token {

  int expirationSeconds = 60 * 60 * 24;

  public RefreshToken() {
    long now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TokenType.REFRESH);
    claims.put("exp", expirationSeconds + now);
  }

  public RefreshToken(String existingToken) {
    claims = setClaims(existingToken);
  }

  public Future<Boolean> isValid() {
    return Future.succeededFuture(Boolean.FALSE);
  }

}
