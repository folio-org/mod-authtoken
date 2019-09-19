package org.folio.auth.authtokenmodule.impl;

import org.folio.auth.authtokenmodule.PermissionsSource;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.folio.auth.authtokenmodule.PermissionData;


/**
 *
 * @author kurt
 */
public class DummyPermissionsSource implements PermissionsSource {

  @Override
  public Future<JsonArray> getPermissionsForUser(String username, String tenant,
      String okapiUrl, String requestToken, String requestId) {
    Future<JsonArray> future = Future.future();
    future.complete(new JsonArray());
    return future;
  }

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid, String tenant, 
      String okapiUrl, String requestToken, String requestId, JsonArray permissions, String key) {
    PermissionData permissionData = new PermissionData();
    permissionData.setExpandedPermissions(permissions);
    return Future.succeededFuture(permissionData);
  }

}
