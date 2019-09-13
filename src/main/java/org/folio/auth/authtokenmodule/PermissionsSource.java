package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;

/**
 *
 * @author kurt
 */
public interface PermissionsSource {

  public void setOkapiUrl(String url);

  Future<JsonArray> getPermissionsForUser(String username, String tenant,
    String requestToken, String requestId);

  Future<JsonArray> expandPermissions(JsonArray permissions, String tenant,
    String requestToken, String requestId);

  Future<PermissionData> getUserAndExpandedPermissions(String userid, String tenant, String requestToken,
    String requestId, JsonArray permissions, String key);

}


