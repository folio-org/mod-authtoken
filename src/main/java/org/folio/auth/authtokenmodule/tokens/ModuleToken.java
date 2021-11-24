package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.Future;

public class ModuleToken extends Token {

  public ModuleToken(String tenant, String username, String userId, String moduleName, JsonArray permissionList) {
    claims = new JsonObject();
    claims.put("type", TokenType.MODULE);
    claims.put("sub", username);
    claims.put("tenant", tenant);
    claims.put("module", moduleName);
    claims.put("user_id", userId);
    claims.put("extra_permissions", permissionList);
  }

  public ModuleToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<Void> validate() {
    // TODO Determine what to validate on here.
    // TODO Module tokens may not require validation .
    return Future.succeededFuture();
  }
}
