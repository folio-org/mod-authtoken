package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

public class RequestToken extends Token {
  
  public RequestToken(String tenant, JsonArray extraPerms) {
    claims = new JsonObject()
    .put("type", TokenType.REQUEST)
    .put("tenant", tenant)
    .put("sub", "_AUTHZ_MODULE_")
    .put("dummy", true) // TODO Is a RequestToken a "dummy token?"
    .put("extra_perms", extraPerms);
  }

  public Future<Token> validate(MultiMap headers) {
    try { 
      validateCommon(headers);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    return Future.succeededFuture(this);
  }
}
