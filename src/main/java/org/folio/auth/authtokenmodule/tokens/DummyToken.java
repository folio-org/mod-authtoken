package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;

public class DummyToken extends Token {
  public DummyToken(String username, String tenant) {
    claims = new JsonObject();
    claims.put("type", TokenType.DUMMY);
    claims.put("sub", username);
    claims.put("tenant", tenant);
    claims.put("dummy", true);
  }

  public DummyToken(String jwtSource) {
    claims = getClaims(jwtSource);
    source = jwtSource;
  }

  public Future<Void> validate() {
    // TODO Determine what to validate on here.
    return Future.succeededFuture();
  }
}
