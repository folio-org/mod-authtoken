package org.folio.auth.authtokenmodule;

import java.time.Instant;

import io.netty.util.concurrent.FailedFuture;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

public class AccessToken extends Token {
  public AccessToken(String tenant, String username, String userId) {
    claims = new JsonObject();
    claims.put("iat", Instant.now().getEpochSecond());
    claims.put("tenant", tenant);
    claims.put("sub", username);
    claims.put("user_id", userId);
    claims.put("type", TokenType.ACCESS);

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

    // TODO Validate anything special to this token type.
    // TODO Validate the exp claim.

    return Future.succeededFuture();
  }

}
