package org.folio.auth.authtokenmodule.impl;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import org.folio.auth.authtokenmodule.PermissionsSource;
import org.folio.auth.authtokenmodule.PermissionData;

/**
 *
 * @author kurt
 */
public class DummyPermissionsSource implements PermissionsSource {

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid, String tenant, 
      String okapiUrl, String requestToken, String requestId, JsonArray permissions, String key) {
    PermissionData permissionData = new PermissionData();
    permissionData.setExpandedPermissions(permissions);
    return Future.succeededFuture(permissionData);
  }

}
