package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;

import java.util.Calendar;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

public class DummyToken extends Token {
  public static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";

  public DummyToken(String tenant, String remoteIpAddress) {
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    Date now = Calendar.getInstance().getTime();
    String username = UNDEFINED_USER_NAME + remoteIpAddress + "__" + df.format(now);
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

  public Future<Void> validate(MultiMap headers) {
    // TODO Determine what to validate on here.
    return Future.succeededFuture();
  }
}
