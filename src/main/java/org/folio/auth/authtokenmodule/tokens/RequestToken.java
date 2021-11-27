package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

public class RequestToken extends Token {
  
  public RequestToken(String tenant, JsonArray extraPerms) {
    claims = new JsonObject()
    .put("type", TokenType.ACCESS)
    .put("tenant", tenant)
    .put("sub", "_AUTHZ_MODULE_")
    .put("dummy", true)
    .put("extra_perms", extraPerms);
  }

  public Future<Void> validate(MultiMap headers) {
    return Future.succeededFuture();
  }
}
