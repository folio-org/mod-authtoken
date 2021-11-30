package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;

import java.util.Calendar;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import io.vertx.core.json.JsonArray;

public class DummyToken extends Token {
  public DummyToken(String tenant, String remoteIpAddress) {
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    Date now = Calendar.getInstance().getTime();
    String username = Token.UNDEFINED_USER_NAME + remoteIpAddress + "__" + df.format(now);
    claims = new JsonObject()
    .put("type", TokenType.DUMMY)
    .put("sub", username)
    .put("tenant", tenant)
    .put("dummy", true);
  }

  public DummyToken(String tenant, JsonArray extraPerms) {
    claims = new JsonObject()
    .put("type", TokenType.DUMMY)
    .put("tenant", tenant)
    .put("sub", "_AUTHZ_MODULE_")
    .put("dummy", true)
    .put("extra_perms", extraPerms);
  }

  public DummyToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validate(HttpServerRequest request) {
    try { 
      validateCommon(request);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    }

    return Future.succeededFuture(this);
  }
}
