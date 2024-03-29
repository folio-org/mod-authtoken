package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.Future;

/**
 * Module tokens are generated by this module which contain the original token
 * plus the permissions granted for the module.
 */

public class ModuleToken extends Token {
  /**
   * A string representation of the type of this token.
   */
  public static final String TYPE = "module";

  /**
   * Create a new module token.
   * @param tenant The current tenant.
   * @param username The username associated with the token.
   * @param userId The user id associated with the token.
   * @param moduleName The module's name.
   * @param permissionList A list of permissions granted to the module.
   */
  public ModuleToken(String tenant, String username, String userId, String moduleName, JsonArray permissionList) {
    claims = new JsonObject()
    .put("type", TYPE)
    .put("tenant", tenant)
    .put("sub", username)
    .put("module", moduleName)
    .put("user_id", userId)
    .put("extra_permissions", permissionList);
  }

  /**
   * Instantiate a module token object from a module token that has been received.
   * @param jwtSource The token that has been provided.
   * @param sourceClaims The claims for the source token.
   */
  public ModuleToken(String jwtSource, JsonObject sourceClaims) {
    claims = sourceClaims;
    source = jwtSource;
  }

  protected Future<Token> validateContext(TokenValidationContext context) {
    return validateCommon(context);
  }
}
