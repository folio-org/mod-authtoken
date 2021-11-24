package org.folio.auth.authtokenmodule.tokens;

import java.time.Instant;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

public class AccessToken extends Token {
  // TODO This could be obtained from the env.
  int expirationSeconds = 60 * 10;

  public AccessToken(String tenant, String username, String userId) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TokenType.ACCESS);
    claims.put("iat", now);
    claims.put("exp", now + expirationSeconds);
    claims.put("tenant", tenant);
    claims.put("sub", username);
    claims.put("user_id", userId);

    // TODO Add exp
  }

  public AccessToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<Void> validate() {
    try { 
      validateCommon();
    } catch (Exception e) {
      return Future.failedFuture(e);
    }

    // TODO Validate the exp claim andn put behind a system flag.

    return Future.succeededFuture();
  }

}
