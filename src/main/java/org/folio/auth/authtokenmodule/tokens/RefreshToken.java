package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.UUID;

/**
 * Refresh tokens are provided to obtain a new access token.
 * @see AccessToken
 */
public class RefreshToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String type = "refresh";

  public UUID getId() {
    return UUID.fromString(claims.getString("jti"));
  }

  public UUID getUserId() {
    return UUID.fromString(claims.getString("user_id"));
  }

  public long getIssuedAt() {
    return claims.getLong("iat");
  }

  // TODO This could be obtained from the env.
  int expirationSeconds = 60 * 60 * 24;

  /**
   * Create a new refresh token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   * @param address The http address of issuer of the token.
   */
  public RefreshToken(String tenant, String username, String userId, String address) {
    long now = Instant.now().getEpochSecond();
    claims = new JsonObject()
    .put("type", type)
    .put("exp", now + expirationSeconds)
    .put("iat", now)
    .put("sub", username)
    .put("user_id", userId)
    .put("tenant", tenant)
    .put("address", address)
    .put("jti", UUID.randomUUID().toString())
    .put("prn", "refresh");
  }

  /**
   * Instantiate an refresh token object from a refresh token which has been provided
   * to obtain a new access token.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public RefreshToken(String sourceJwt, JsonObject sourceClaims) {
    source = sourceJwt;
    claims = sourceClaims;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    try {
      validateCommon(context.getHttpServerRequest());
    } catch (Exception e) {
      return Future.failedFuture(e);
    }

    String address = context.getHttpServerRequest().remoteAddress().host();
    if (!address.equals(claims.getString("address"))) {
      var e = new TokenValidationException("Issuing address does not match for refresh token", 401);
      return Future.failedFuture(e);
    }

    Long nowTime = Instant.now().getEpochSecond();
    Long expiration = claims.getLong("exp");
    if (expiration < nowTime) {
      var e = new TokenValidationException("Attempt to refresh with expired refresh token", 401);
      return Future.failedFuture(e);
    }

    // TODO Check storage to ensure that token has not yet been used.
    // TODO If the token has been used, revoke all RTs for this user_id.

    return Future.succeededFuture(this);
  }

}
