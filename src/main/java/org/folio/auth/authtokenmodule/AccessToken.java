package org.folio.auth.authtokenmodule;

import java.time.Instant;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

public class AccessToken extends Token {
  public AccessToken(String tenant, String userId) {
    claims = new JsonObject();
    claims.put("iat", Instant.now());
    claims.put("tenant", tenant);
    claims.put("sub", userId);
    claims.put("type", TokenType.ACCESS);

    // TODO Add exp
  }

  public AccessToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<TokenValidationResult> isValid() {
    TokenValidationResult common = validateCommon();
    if (!common.isValid)
      return Future.succeededFuture(common);

    // TODO Validate the exp claim.

    return Future.succeededFuture(TokenValidationResult.success());
  }

}
