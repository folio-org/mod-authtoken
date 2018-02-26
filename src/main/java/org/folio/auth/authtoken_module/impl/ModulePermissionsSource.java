package org.folio.auth.authtoken_module.impl;

import io.vertx.core.CompositeFuture;
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
import java.util.HashMap;
import java.util.Map;
import org.folio.auth.authtoken_module.PermissionData;

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
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private final HttpClient client;
  private Map<String, CacheEntry> cacheMap;
  private boolean cacheEntries;

  public ModulePermissionsSource(Vertx vertx, int timeout, boolean cache) {
    //permissionsModuleUrl = url;
    cacheEntries = cache;
    this.vertx = vertx;
    HttpClientOptions options = new HttpClientOptions();
    options.setConnectTimeout(timeout * 1000);
    client = vertx.createHttpClient(options);
    if(cache) {
      cacheMap = new HashMap<>();
    }
  }
  
  @Override
  public void setOkapiUrl(String url) {
    okapiUrl = url;
    if (!okapiUrl.endsWith("/")) {
      okapiUrl = okapiUrl + "/";
    }
  }

  @Override
  public void setRequestToken(String token) {
    requestToken = token;
  }

  @Override
  public void setAuthApiKey(String key) {
    authApiKey = key;
  }

  @Override
  public void setTenant(String tenant) {
    this.tenant = tenant;
  }

  @Override
  public Future<JsonArray> getPermissionsForUser(String userid) {
    Future<JsonArray> future = Future.future();
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
      HttpClientRequest req = client.getAbs(requestUrl, res -> {
        res.bodyHandler(body -> {
          try {
            if (res.statusCode() != 200) {
              String message = "Expected 200, got result " + res.statusCode()
                      + " : " + body.toString();
              future.fail(message);
              logger.error("Error expanding " + permissions.encode() + ": " + message);
            } else {
              logger.info("Got result from permissions module: " + body.toString());
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

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid, JsonArray permissions) {
    System.out.println("getUserAndExpandedPermissions, userid=" + userid + "permissions=" +
            permissions.encode());
    logger.info("Retrieving permissions for userid "  + userid + " and expanding permissions for " +
      permissions.encode());
    CacheEntry[] currentCache = new CacheEntry[1];
    if(cacheEntries) {
      currentCache[0] = cacheMap.getOrDefault(userid, null);
      if(currentCache[0] == null ||
              (System.currentTimeMillis() - currentCache[0].getTimestamp()) / 1000 > 10 ) {
        logger.debug("Cache expired, discarding");
        currentCache[0] = new CacheEntry();
        if(userid != null) {
          cacheMap.put(userid, currentCache[0]);
        }
      } 
    }
    Future<PermissionData> future = Future.future();
    Future<JsonArray> userPermsFuture;
    if(cacheEntries && currentCache[0].getPermissions() != null) {
      userPermsFuture = Future.succeededFuture(currentCache[0].getPermissions());
    } else {
      userPermsFuture = getPermissionsForUser(userid);
    }
    Future<JsonArray> expandedPermsFuture;
    if(cacheEntries && currentCache[0].getExpandedPermissions() != null) {
      expandedPermsFuture = Future.succeededFuture(currentCache[0].getExpandedPermissions());
    } else {
      expandedPermsFuture = expandPermissions(permissions);
    }
    CompositeFuture compositeFuture = CompositeFuture.all(userPermsFuture, expandedPermsFuture);
    compositeFuture.setHandler(compositeRes -> {
      if(compositeFuture.failed()) {
        future.fail(compositeFuture.cause());
      } else {
        PermissionData permissionData = new PermissionData();
        permissionData.setUserPermissions(userPermsFuture.result());
        permissionData.setExpandedPermissions(expandedPermsFuture.result());
        if(cacheEntries) {
          JsonArray copiedUserPerms = new JsonArray();
          JsonArray copiedExpandedPerms = new JsonArray();
          for(Object p : userPermsFuture.result()) {
            copiedUserPerms.add(p);
          }
          currentCache[0].setPermissions(copiedUserPerms);
          for(Object p : expandedPermsFuture.result()) {
            copiedExpandedPerms.add(p);
          }
          currentCache[0].setExpandedPermissions(copiedExpandedPerms);
        }
        future.complete(permissionData);
        System.out.println("completing future with user permissions=" + permissionData.getUserPermissions().encode() +
                ", expanded permissions=" + permissionData.getExpandedPermissions().encode());
      }
    });
    return future;
  }

}

class CacheEntry {
  private Long timestamp;
  private JsonArray permissions;
  private JsonArray expandedPermissions;

  public CacheEntry() {
    timestamp = System.currentTimeMillis();
    permissions = null;
    expandedPermissions = null;
  }

  public Long getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(Long timestamp) {
    this.timestamp = timestamp;
  }

  public JsonArray getPermissions() {
    return permissions;
  }

  public void setPermissions(JsonArray permissions) {
    this.permissions = permissions;
  }

  public JsonArray getExpandedPermissions() {
    return expandedPermissions;
  }

  public void setExpandedPermissions(JsonArray expandedPermissions) {
    this.expandedPermissions = expandedPermissions;
  }
}
