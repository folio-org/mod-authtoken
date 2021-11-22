package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.time.Instant;

public class RefreshToken extends Token {

  // TODO This could be obtained from the env.
  int expirationSeconds = 60 * 60 * 24;

  public RefreshToken(String tenant, String userId) {
    long now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TokenType.REFRESH);
    claims.put("exp", expirationSeconds + now);
    claims.put("sub", userId);
    claims.put("tenant", tenant);

    // TODO Add other claims here.
  }

  public RefreshToken(String sourceJwt) {
    source = sourceJwt;
    claims = getClaims(sourceJwt);
  }

  public Future<TokenValidationResult> isValid() {
    TokenValidationResult common = validateCommon();
    if (!common.isValid)
      return Future.succeededFuture(common);
    
    return Future.succeededFuture(TokenValidationResult.success());
  }

}
