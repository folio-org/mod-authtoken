package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.UUID;

import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;

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

  public long getExpiresAt() {
    return claims.getLong("exp");
  }

  /**
   * Should only be used by tests.
   * @param to The epoch seconds time stamp to set the exp claim to.
   */
  public void setExpiresAt(long to) {
    claims.put("exp", to);
  }

  int expirationSeconds = TOKEN_EXPIRATION_SECONDS;

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

    if (tokenHasExpired(claims)) {
      var e = new TokenValidationException("Attempt to refresh with expired refresh token", 401);
      return Future.failedFuture(e);
    }

    var refreshTokenStore = (RefreshTokenStore)context.getTokenStore();
    return refreshTokenStore.checkTokenNotRevoked(this).compose(x -> {
      return Future.succeededFuture(this);
    });
  }

}
