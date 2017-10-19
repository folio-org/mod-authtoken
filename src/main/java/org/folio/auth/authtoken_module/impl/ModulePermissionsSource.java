package org.folio.auth.authtoken_module.impl;

import java.util.StringJoiner;
import org.folio.auth.authtoken_module.PermissionsSource;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.net.URLEncoder;

/**
 *
 * @author kurt
 */
public class ModulePermissionsSource implements PermissionsSource {

  private String okapiUrl = null;
  private Vertx vertx;
  private String requestToken;
  private String authApiKey = "";
  private String tenant;
  private int timeout = 10;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");

  public ModulePermissionsSource(Vertx vertx) {
    //permissionsModuleUrl = url;
    this.vertx = vertx;
  }

  public void setOkapiUrl(String url) {
    okapiUrl = url;
    if (!okapiUrl.endsWith("/")) {
      okapiUrl = okapiUrl + "/";
    }
  }

  public void setRequestToken(String token) {
    requestToken = token;
  }

  public void setAuthApiKey(String key) {
    authApiKey = key;
  }

  public void setTenant(String tenant) {
    this.tenant = tenant;
  }

  public void setRequestTimeout(int seconds) {
    this.timeout = seconds;
  }

  @Override
  public Future<JsonArray> getPermissionsForUser(String userid) {
    Future<JsonArray> future = Future.future();
    HttpClientOptions options = new HttpClientOptions();
    options.setConnectTimeout(timeout);
    HttpClient client = vertx.createHttpClient(options);
    String okapiUrlCandidate = "http://localhost:9130/";
    if (okapiUrl != null) {
      okapiUrlCandidate = okapiUrl;
    }
    final String okapiUrlFinal = okapiUrlCandidate;
    String permUserRequestUrl = okapiUrlFinal + "perms/users?query=userId==" + userid;
    logger.debug("Requesting permissions user object from URL at " + permUserRequestUrl);
    HttpClientRequest permUserReq = client.getAbs(permUserRequestUrl, permUserRes -> {
      permUserRes.bodyHandler(permUserBody -> {
        if (permUserRes.statusCode() != 200) {
          future.fail("Expected return code 200, got " + permUserRes.statusCode()
                  + " : " + permUserBody.toString());
        } else {
          JsonObject permUserResults = new JsonObject(permUserBody.toString());
          JsonObject permUser = permUserResults.getJsonArray("permissionUsers").getJsonObject(0);
          final String requestUrl = okapiUrlFinal + "perms/users/" + permUser.getString("id") + "/permissions?expanded=true";
          logger.debug("Requesting permissions from URL at " + requestUrl);
          HttpClientRequest req = client.getAbs(requestUrl, res -> {
            if (res.statusCode() == 200) {
              res.bodyHandler(res2 -> {
                JsonObject permissionsObject;
                try {
                  permissionsObject = new JsonObject(res2.toString());
                } catch (Exception e) {
                  logger.debug("Error parsing permissions object: " + e.getLocalizedMessage());
                  permissionsObject = null;
                }
                if (permissionsObject != null && permissionsObject.getJsonArray("permissionNames") != null) {
                  logger.debug("Got permissions: " + permissionsObject.getJsonArray("permissionNames").encodePrettily());
                  future.complete(permissionsObject.getJsonArray("permissionNames"));
                } else {
                  logger.debug("Got malformed/empty permissions object");
                  future.fail("Got malformed/empty permissions object");
                }
              });
            } else if (res.statusCode() == 404) {
              //In the event of a 404, that means that the permissions user
              //doesn't exist, so we'll return an empty list to indicate no permissions
              future.complete(new JsonArray());
            } else {
              //future.fail("Unable to retrieve permissions");
              res.bodyHandler(res2 -> {
                String failMessage = "Unable to retrieve permissions (code " + res.statusCode() + "): " + res2.toString();
                logger.debug(failMessage);
                future.fail(failMessage);
              });
            }
          });

          req.exceptionHandler(exception -> {
            future.fail(exception);
          });

          req.headers().add("X-Okapi-Token", requestToken);
          req.headers().add("X-Okapi-Tenant", tenant);
          req.headers().add("Content-Type", "application/json");
          req.headers().add("Accept", "application/json");
          req.end();
        }
      });
      permUserRes.exceptionHandler(e -> {
        future.fail(e);
      });
    });
    permUserReq.headers()
            .add("X-Okapi-Token", requestToken)
            .add("X-Okapi-Tenant", tenant)
            .add("Content-Type", "application/json")
            .add("Accept", "application/json");
    permUserReq.end();
    return future;
  }

  @Override
  public Future<JsonArray> expandPermissions(JsonArray permissions) {
    Future<JsonArray> future = Future.future();
    if (permissions.isEmpty()) {
      future.complete(new JsonArray());
      return future;
    }
    logger.debug("Expanding permissions array: " + permissions.encode());
    String query = "(";
    StringJoiner joiner = new StringJoiner(" or ");
    for (Object ob : permissions) {
      String permissionName = (String) ob;
      joiner.add("permissionName==" + permissionName + "");
    }
    query = query + joiner.toString() + ")";
    String okapiUrlFinal = "http://localhost:9130/"; //Fallback
    if (okapiUrl != null) {
      okapiUrlFinal = okapiUrl;
    }
    try {
      String requestUrl = okapiUrlFinal + "perms/permissions?"
              + URLEncoder.encode("expandSubs=true&query=" + query, "UTF-8");
      logger.debug("Requesting expanded permissions from URL at " + requestUrl);
      HttpClientOptions options = new HttpClientOptions();
      //options.setConnectTimeout(timeout);
      HttpClient client = vertx.createHttpClient(options);
      HttpClientRequest req = client.getAbs(requestUrl, res -> {
        res.bodyHandler(body -> {
          try {
            if (res.statusCode() != 200) {
              String message = "Expected 200, got result " + res.statusCode()
                      + " : " + body.toString();
              future.fail(message);
              logger.error("Error expanding " + permissions.encode() + ": " + message);
            } else {
              JsonObject result = new JsonObject(body.toString());
              JsonArray expandedPermissions = new JsonArray();
              for (Object ob : permissions) {
                String permName = (String) ob;
                if (!expandedPermissions.contains(permName)) {
                  expandedPermissions.add(permName);
                }
              }
              for (Object ob : result.getJsonArray("permissions")) {
                JsonObject permissionObject = (JsonObject) ob;
                if (!expandedPermissions.contains(permissionObject.getString("permissionName"))) {
                  expandedPermissions.add(permissionObject.getString("permissionName"));
                }
                JsonArray subPermissionArray = permissionObject.getJsonArray("subPermissions");
                if (subPermissionArray != null) {
                  for (Object subOb : subPermissionArray) {
                    if (subOb instanceof String) {
                      String subPermissionName = (String) subOb;
                      if (!expandedPermissions.contains(subPermissionName)) {
                        expandedPermissions.add(subPermissionName);
                      }
                    } else {
                      JsonObject subPermissionObject = (JsonObject) subOb;
                      String subPermissionName = subPermissionObject.getString("permissionName");
                      if (!expandedPermissions.contains(subPermissionName)) {
                        expandedPermissions.add(subPermissionName);
                      }
                      JsonArray subSubPermissionArray = subPermissionObject.getJsonArray("subPermissions");
                      if (subSubPermissionArray != null) {
                        for (Object subSubOb : subSubPermissionArray) {
                          String subSubPermissionName = (String) subSubOb;
                          if (!expandedPermissions.contains(subSubPermissionName)) {
                            expandedPermissions.add(subSubPermissionName);
                          }
                        }
                      }
                    }
                  }
                }
              }
              future.complete(expandedPermissions);
            }
          } catch (Exception e) {
            logger.error(e.getLocalizedMessage(), e);
            future.fail("Unable to expand permissions: " + e.getLocalizedMessage());
          }
        });
        res.exceptionHandler(e -> {
          future.fail(e);
        });
      });
      req.putHeader("X-Okapi-Token", requestToken)
              .putHeader("X-Okapi-Tenant", tenant)
              .putHeader("Content-Type", "application/json")
              .putHeader("Accept", "application/json");

      req.exceptionHandler(e -> {
        future.fail(e);
      });

      req.end();
    } catch (Exception e) {
      logger.error(e.getLocalizedMessage(), e);
      future.fail("Unable to expand permissions: " + e.getLocalizedMessage());
    }

    return future;
  }

}
