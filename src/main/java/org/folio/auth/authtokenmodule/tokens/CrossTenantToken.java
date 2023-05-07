package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

import java.time.Instant;

public class CrossTenantToken extends Token {
  public static final String TYPE = "cross-tenant";

  public CrossTenantToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  public CrossTenantToken(String tenant, String username, String userId) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TYPE);
    claims.put("iat", now);
    claims.put("tenant", tenant);
    claims.put("sub", username);
    claims.put("user_id", userId);
  }

  @Override
  protected Future<Token> validateContext(TokenValidationContext context) {
    try {
      validateCommon(context.getHttpServerRequest());
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    return Future.succeededFuture(this);
  }

  @Override
  protected boolean isTenantMismatchCheckEnabled() {
    return false;
  }
}
