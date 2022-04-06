package org.folio.auth.authtokenmodule.tokens;

import java.time.Instant;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

/**
 * Access tokens are obtained either when a user authenticates or when a valid
 * refresh token is provided. The legacy access token is a non-expiring access token
 * which should eventually be depreciated.
 * @see RefreshToken
 */
public class LegacyAccessToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String type = "legacy-access";

  /**
   * Create a new access token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   */
  public LegacyAccessToken(String tenant, String username, String userId) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", type);
    claims.put("iat", now);
    claims.put("tenant", tenant);
    claims.put("sub", username);
    claims.put("user_id", userId);
  }

  /**
   * Instantiate an access token object from a token which has been provided
   * for authorization.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public LegacyAccessToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    try {
      validateCommon(context.getHttpServerRequest());
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    return Future.succeededFuture(this);
  }

}
