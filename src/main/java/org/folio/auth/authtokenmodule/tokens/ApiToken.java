package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;

import java.time.Instant;
import java.util.UUID;

import io.vertx.core.Future;

/**
 * An API token is a non-expiring token that authorizes API Access.
 */
public class ApiToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String TYPE = "api";

  public UUID getId() {
    return UUID.fromString(claims.getString("jti"));
  }

  public long getIssuedAt() {
    return claims.getLong("iat");
  }

  /**
   * Create a new ApiToken.
   * @param tenant The current tenant.
   */
  public ApiToken(String tenant) {
    claims = new JsonObject();
    claims.put("type", TYPE);
    claims.put("tenant", tenant);
    long now = Instant.now().getEpochSecond();
    claims.put("iat", now);
    claims.put("jti", UUID.randomUUID().toString());

    // TODO Determine if API tokens have a sub and a user_id.
    // It could be that these belong to the user who manages the API token.
    // However the permissions need to be bound to the API token, not the user
    // since each API token should have its own permissions.

    // TODO Determine what other properties API tokens need.
  }

  /**
   * Instantiate an ApiToken object from a token which has been provided for
   * authorization.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public ApiToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    try {
      validateCommon(context.getHttpServerRequest());
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    // TODO Validate the API token by checking that it exists in storage,
    // hasn't been revoked, etc.

    return Future.succeededFuture(this);
  }
}
