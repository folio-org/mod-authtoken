package org.folio.auth.authtokenmodule.tokens;

import java.time.Instant;
import java.util.UUID;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;

/**
 * Access tokens are obtained either when a user authenticates or when a valid
 * refresh token is provided.
 * @see RefreshToken
 */
public class AccessToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String TYPE = "access";

  public static final long DEFAULT_EXPIRATION_SECONDS = 600;

  public String getExpiresAtInIso8601Format() {
    return Instant.ofEpochSecond(claims.getLong("exp")).toString();
  }

  public UUID getUserId() {
    return UUID.fromString(claims.getString("user_id"));
  }

  /**
   * Create a new access token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   * @param expirationSeconds The seconds after which this token will be considered expired.
   */
  public AccessToken(String tenant, String username, String userId, long expirationSeconds) {
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
    return validateCommon(context).compose(token -> tokenIsExpired() ?
      Future.failedFuture(new TokenValidationException("Access token has expired", 401)) :
      Future.succeededFuture(token));
  }
}
