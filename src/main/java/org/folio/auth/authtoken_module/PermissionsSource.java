package org.folio.auth.authtoken_module;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;

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

}
