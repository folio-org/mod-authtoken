package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;

/**
 * An API token is a non-expiring token that authorizes API Access.
 */
public class ApiToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String type = "api";

  /**
   * Create a new ApiToken.
   * @param tenant The current tenant.
   * @param userId The user id of the user who is associated with the token.
   */
  public ApiToken(String tenant, String userId) {
    claims = new JsonObject();
    claims.put("type", type);
    claims.put("tenant", tenant);

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

  protected Future<Token> validate(HttpServerRequest request) {
    try { 
      validateCommon(request);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    // TODO Validate the API token by checking that it exists in storage,
    // hasn't been revoked, etc.

    return Future.succeededFuture(this);
  }
}
