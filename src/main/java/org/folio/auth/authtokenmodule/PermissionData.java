package org.folio.auth.authtokenmodule;

import io.vertx.core.json.JsonArray;

/**
 *
 * @author kurt
 */
public class PermissionData {
  private JsonArray userPermissions;
  private JsonArray expandedPermissions;

  public PermissionData() {
    userPermissions = new JsonArray();
    expandedPermissions = new JsonArray();
  }

  public JsonArray getUserPermissions() {
    return userPermissions;
  }

  public void setUserPermissions(JsonArray userPermissions) {
    this.userPermissions = userPermissions;
  }

  public JsonArray getExpandedPermissions() {
    return expandedPermissions;
  }

  public void setExpandedPermissions(JsonArray expandedPermissions) {
    this.expandedPermissions = expandedPermissions;
  }
}
