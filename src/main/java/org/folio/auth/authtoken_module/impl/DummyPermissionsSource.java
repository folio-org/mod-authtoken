package org.folio.auth.authtoken_module.impl;

import org.folio.auth.authtoken_module.PermissionsSource;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.folio.auth.authtoken_module.PermissionData;


/**
 *
 * @author kurt
 */
public class DummyPermissionsSource implements PermissionsSource {

  @Override
  public Future<JsonArray> getPermissionsForUser(String username) {
    Future<JsonArray> future = Future.future();
    future.complete(new JsonArray());
    return future;
  }

  @Override
  public void setOkapiUrl(String url) {
    return;
  }

  @Override
  public void setRequestToken(String token) {
    return;
  }

  @Override
  public void setAuthApiKey(String key) {
    return;
  }

  @Override
  public void setTenant(String tenant) {
    return;
  }

  @Override
  public Future<JsonArray> expandPermissions(JsonArray permissions) {
    Future<JsonArray> future = Future.future();
    future.complete(permissions);
    return future;
  }

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid, 
          JsonArray permissions) {
    PermissionData permissionData = new PermissionData();
    permissionData.setExpandedPermissions(permissions);
    return Future.succeededFuture(permissionData);
  }

}
