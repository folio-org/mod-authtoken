package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.UUID;

import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.tokens.ttl.TokenTTL;

/**
 * Refresh tokens are provided to obtain a new access token.
 * @see AccessToken
 */

public class RefreshToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String TYPE = "refresh";

  /**
   * Time after which token is expired. 604800 seconds = 7 days.
   */
  public static final long DEFALUT_EXPIRATION_SECONDS = 604800;

  public UUID getId() {
    return UUID.fromString(claims.getString("jti"));
  }

  public UUID getUserId() {
    return UUID.fromString(claims.getString("user_id"));
  }

  public long getExpiresAt() {
    return claims.getLong("exp");
  }

  public String getExpiresAtInIso8601Format() {
    return Instant.ofEpochSecond(claims.getLong("exp")).toString();
  }

  /**
   * Create a new refresh token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   * @param address The http address of issuer of the token.
   * @param expirationSeconds The seconds after which this token will be considered expired.
   *
   */
  public RefreshToken(String tenant, String username, String userId, String address, long expirationSeconds) {
    long now = Instant.now().getEpochSecond();
    claims = new JsonObject()
    .put("type", TYPE)
    .put("exp", now + expirationSeconds)
    .put("iat", now)
    .put("sub", username)
    .put("user_id", userId)
    .put("tenant", tenant)
    .put("address", address)
    .put("jti", UUID.randomUUID().toString())
    .put("prn", TYPE);
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
    return validateCommon(context)
      .map(context.getHttpServerRequest().remoteAddress().host())
      .compose(address -> address.equals(claims.getString("address")) ? Future.succeededFuture()
        : Future.failedFuture(new TokenValidationException("Issuing address does not match for refresh token", 401)))
      .compose(aRes -> tokenIsExpired() ?
        Future.failedFuture(new TokenValidationException("Attempt to refresh with expired refresh token", 401))
        : Future.succeededFuture())
      .map((RefreshTokenStore) context.getTokenStore())
      .compose(refreshTokenStore -> refreshTokenStore.checkTokenNotRevoked(this))
      .map(this);
  }
}
