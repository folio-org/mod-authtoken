package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.time.Instant;

public class DummyTokenExpiring extends Token {
  public static final String TYPE = "dummy-expiring";

  /**
   * Create a dummy token to be used to request permissions.
   * @param tenant tenant that is token is part.
   * @param extraPerms permissions to be given
   * @param sub dummy user component.
   * @param expirationSeconds The seconds after which this token will be considered expired.
   */
  public DummyTokenExpiring(String tenant, JsonArray extraPerms, String sub, long expirationSeconds) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject()
      .put("type", TYPE)
      .put("tenant", tenant)
      .put("sub", sub)
      .put("dummy", true)
      .put("extra_permissions", extraPerms)
      .put("exp", now + expirationSeconds);
  }

  /**
   * Instantiate a dummy token object from a token which has been provided for
   * authorization.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public DummyTokenExpiring(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    return validateCommon(context).compose(token -> tokenIsExpired() ?
      Future.failedFuture(new TokenValidationException("Token has expired", 401)) :
      Future.succeededFuture(token));
  }
}
