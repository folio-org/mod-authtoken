package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;

public class ModuleToken extends Token {

  public ModuleToken(String tenant, String username, String userId, String moduleName, JsonArray permissionList) {
    claims = new JsonObject()
    .put("type", TokenType.MODULE)
    .put("tenant", tenant)
    .put("sub", username)
    .put("module", moduleName)
    .put("user_id", userId)
    .put("extra_permissions", permissionList);
  }

  public ModuleToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<Token> validate(MultiMap headers) {
    try { 
      validateCommon(headers);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }
    // TODO Determine what to validate on here.
    // TODO Module tokens may not require validation .
    return Future.succeededFuture(this);
  }
}
