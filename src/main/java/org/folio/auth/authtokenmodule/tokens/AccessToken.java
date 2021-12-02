package org.folio.auth.authtokenmodule.tokens;

import java.time.Instant;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;

/**
 * Access tokens are obtained either when a user authenticates or when a valid
 * refresh token is provided.
 * @see RefreshToken
 */
public class AccessToken extends Token {
  // TODO This could be obtained from the env.
  int expirationSeconds = 60 * 10;

  /**
   * Create a new access token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   */
  public AccessToken(String tenant, String username, String userId) {
    var now = Instant.now().getEpochSecond();
    claims = new JsonObject();
    claims.put("type", TokenType.ACCESS);
    claims.put("iat", now);
    claims.put("exp", now + expirationSeconds);
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
  public AccessToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validate(HttpServerRequest request) {
    try { 
      validateCommon(request);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    // TODO Validate the exp claim and put behind a system flag.

    return Future.succeededFuture(this);
  }

}
