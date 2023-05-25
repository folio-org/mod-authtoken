package org.folio.auth.authtokenmodule.tokens;

import java.time.Instant;
import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

/**
 * Access tokens are obtained either when a user authenticates or when a valid
 * refresh token is provided.
 * @see RefreshToken
 */
public class AccessToken extends Token {
  int expirationSeconds = TOKEN_EXPIRATION_SECONDS;

  /**
   * A string representation of the type of this token.
   */
  public static final String TYPE = "access";

  /**
   * Create a new access token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   */
  public AccessToken(String tenant, String username, String userId) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TYPE);
    claims.put("iat", now);
    claims.put("tenant", tenant);
    claims.put("sub", username);
    claims.put("user_id", userId);
    claims.put("exp", now + expirationSeconds);
  }

  /**
   * Instantiate an access token object from a token which has been provided
   * for authorization.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public AccessToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    try {
      validateCommon(context.getHttpServerRequest());
    } catch (TokenValidationException e) {
      return handleCrossTenantRequest(e, context);
    }

    if (tokenIsExpired()) {
      var e = new TokenValidationException("Access token has expired", 401);
      return Future.failedFuture(e);
    }

    return Future.succeededFuture(this);
  }

}
