package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 *
 * @author kurt
 */
public interface PermissionsSource {

  public void setOkapiUrl(String url);
  public void setRequestToken(String token);
  public void setAuthApiKey(String key);
  public void setTenant(String tenant);

  Future<JsonArray> getPermissionsForUser(String username);

  Future<JsonArray> expandPermissions(JsonArray permissions);

  Future<PermissionData> getUserAndExpandedPermissions(String userid, JsonArray permissions);

}


