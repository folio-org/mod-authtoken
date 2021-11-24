package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;

public class ApiToken extends Token {
  public ApiToken(String tenant, String username, String userId) {
    claims = new JsonObject();
    claims.put("type", TokenType.API);
    claims.put("tenant", tenant);

    // TODO Determine if API tokens have a sub and a user_id.
    // It could be that these belong to the user who manages the API token.
    // However the permissions need to be bound to the API token, not the user
    // since each API token should have its own permissions.
    // since all API tokens need 
    // claims.put("sub", username);
    // claims.put("user_id", userId);

    // TODO Determine what other properties API tokens need.
  }

  public ApiToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<Void> validate() {
    try { 
      validateCommon();
    } catch (Exception e) {
      return Future.failedFuture(e);
    }

    // TODO Validate the API token by checking that it exists in storage.

    return Future.succeededFuture();
  }
}
