package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;

import java.util.Calendar;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import io.vertx.core.json.JsonArray;

/**
 * Dummy tokens are created by this module in two situations:
 * 1) When a user hasn't yet authenticated.
 * 2) When requesting permissions to prevent a lookup loop.
 */
public class DummyToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String type = "dummy";

  /**
   * Create a new dummy token for a user who hasn't yet authenticated.
   * @param tenant The current tenant.
   * @param remoteIpAddress The remote ip address of the user requiring the dummy
   * token.
   */
  public DummyToken(String tenant, String remoteIpAddress) {
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    Date now = Calendar.getInstance().getTime();
    String username = Token.UNDEFINED_USER_NAME + remoteIpAddress + "__" + df.format(now);
    claims = new JsonObject()
    .put("type", type)
    .put("sub", username)
    .put("tenant", tenant)
    .put("dummy", true);
  }

  /**
   * Create a dummy token to be used to request permissions.
   * @param tenant The current tenant.
   * @param extraPerms The permissions in scope.
   */
  public DummyToken(String tenant, JsonArray extraPerms) {
    claims = new JsonObject()
    .put("type", type)
    .put("tenant", tenant)
    .put("sub", "_AUTHZ_MODULE_")
    .put("dummy", true)
    .put("extra_permissions", extraPerms);
  }

  /**
   * Instantiate a dummy token object from a token which has been provided for
   * authorization. 
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
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
