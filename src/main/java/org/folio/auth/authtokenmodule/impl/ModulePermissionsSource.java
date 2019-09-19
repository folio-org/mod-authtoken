package org.folio.auth.authtokenmodule.impl;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.net.URLEncoder;
import java.util.StringJoiner;
import java.util.UUID;
import org.folio.auth.authtokenmodule.Cache;
import org.folio.auth.authtokenmodule.LimitedSizeMap;
import org.folio.auth.authtokenmodule.PermissionData;
import org.folio.auth.authtokenmodule.PermissionsSource;

/**
 *
 * @author kurt
 */

public class ModulePermissionsSource implements PermissionsSource, Cache {

  private Vertx vertx;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private final HttpClient client;
  private LimitedSizeMap<String, CacheEntry> cacheMap;
  private boolean cacheEntries;
  private final String keyPrefix;
  private final int MAX_CACHE_SIZE = 250;


  public ModulePermissionsSource(Vertx vertx, int timeout, boolean cache) {
    //permissionsModuleUrl = url;
    cacheEntries = cache;
    this.vertx = vertx;
    HttpClientOptions options = new HttpClientOptions();
    options.setConnectTimeout(timeout * 1000);
    client = vertx.createHttpClient(options);
    keyPrefix = UUID.randomUUID().toString();
    if(cache) {
      cacheMap = new LimitedSizeMap<>(MAX_CACHE_SIZE);
    } else {
      cacheMap = null;
    }
  }

  @Override
  public Future<JsonArray> getPermissionsForUser(String userid, String tenant, String okapiUrl,
    String requestToken, String requestId) {
    logger.info("gerPermissionsForUser userid=" + userid);
    Future<JsonArray> future = Future.future();
    String permUserRequestUrl = okapiUrl + "/perms/users?query=userId==" + userid;
    logger.debug("Requesting permissions user object from URL at " + permUserRequestUrl);
    HttpClientRequest permUserReq = client.getAbs(permUserRequestUrl, permUserRes -> {
      permUserRes.bodyHandler(permUserBody -> {
        if (permUserRes.statusCode() != 200) {
          String message = "Expected return code 200, got " + permUserRes.statusCode()
                  + " : " + permUserBody.toString();
          logger.error(message);
          future.fail(message);
        } else {
          JsonObject permUserResults = new JsonObject(permUserBody.toString());
          JsonObject permUser = permUserResults.getJsonArray("permissionUsers").getJsonObject(0);
          final String requestUrl = okapiUrl + "/perms/users/" + permUser.getString("id") + "/permissions?expanded=true";
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
                  logger.debug("Got permissions");
                  future.complete(permissionsObject.getJsonArray("permissionNames"));
                } else {
                  logger.error("Got malformed/empty permissions object");
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
          endRequest(req, requestToken, tenant, requestId);
        }
      });
      permUserRes.exceptionHandler(e -> {
        future.fail(e);
      });
    });
    endRequest(permUserReq, requestToken, tenant, requestId);
    return future;
  }

  private void endRequest(HttpClientRequest req, String requestToken,
    String tenant, String requestId) {
    if (requestId != null) {
      req.headers().add("X-Okapi-Request-Id", requestId);
    }
    req.headers()
      .add("X-Okapi-Token", requestToken)
      .add("X-Okapi-Tenant", tenant)
      .add("Content-Type", "application/json")
      .add("Accept", "application/json");
    req.end();
  }

  private Future<JsonArray> expandPermissions(JsonArray permissions, String tenant, String okapiUrl, String requestToken,
    String requestId) {
    Future<JsonArray> future = Future.future();
    if (permissions.isEmpty()) {
      future.complete(new JsonArray());
      return future;
    }
    logger.debug("Expanding permissions array");
    String query = "(";
    StringJoiner joiner = new StringJoiner(" or ");
    for (Object ob : permissions) {
      String permissionName = (String) ob;
      joiner.add("permissionName==" + permissionName + "");
    }
    query = query + joiner.toString() + ")";
    try {
      String requestUrl = okapiUrl + "/perms/permissions?"
        + "expandSubs=true&query=" + URLEncoder.encode(query, "UTF-8");
      logger.debug("Requesting expanded permissions from URL at " + requestUrl);
      HttpClientRequest req = client.getAbs(requestUrl, res -> {
        res.bodyHandler(body -> handleExpandPermissions(res, body, future, permissions));
        res.exceptionHandler(e -> {
          future.fail(e);
        });
      });
      req.exceptionHandler(e -> {
        future.fail(e);
      });
      endRequest(req, requestToken, tenant, requestId);
    } catch (Exception e) {
      logger.error(e.getLocalizedMessage(), e);
      future.fail("Unable to expand permissions: " + e.getLocalizedMessage());
    }
    return future;
  }

  private void handleExpandPermissions(HttpClientResponse res, Buffer body,
    Future<JsonArray> future, JsonArray permissions) {

    try {
      if (res.statusCode() != 200) {
        String message = "Expected 200, got result " + res.statusCode()
          + " : " + body.toString();
        future.fail(message);
        logger.error("Error expanding " + permissions.encode() + ": " + message);
        return;
      }
      logger.debug("Got result from permissions module");
      JsonArray expandedPermissions = new JsonArray();
      for (Object ob : permissions) {
        String permName = (String) ob;
        if (!expandedPermissions.contains(permName)) {
          expandedPermissions.add(permName);
        }
      }
      JsonObject result = new JsonObject(body.toString());
      parseExpandedPermissions(result, expandedPermissions);
      future.complete(expandedPermissions);
    } catch (Exception e) {
      logger.error(e.getLocalizedMessage(), e);
      future.fail("Unable to expand permissions: " + e.getLocalizedMessage());
    }
  }

  private void parseExpandedPermissions(JsonObject result, JsonArray expandedPermissions) {
    for (Object ob : result.getJsonArray("permissions")) {
      JsonObject permissionObject = (JsonObject) ob;
      String permissionName = permissionObject.getString("permissionName");
      if (!expandedPermissions.contains(permissionName)) {
        expandedPermissions.add(permissionName);
      }
      JsonArray subPermissionArray = permissionObject.getJsonArray("subPermissions");
      if (subPermissionArray == null) {
        continue;
      }
      for (Object subOb : subPermissionArray) {
        if (subOb instanceof String) {
          String subPermissionName = (String) subOb;
          if (!expandedPermissions.contains(subPermissionName)) {
            expandedPermissions.add(subPermissionName);
          }
          continue;
        }
        JsonObject subPermissionObject = (JsonObject) subOb;
        String subPermissionName = subPermissionObject.getString("permissionName");
        if (!expandedPermissions.contains(subPermissionName)) {
          expandedPermissions.add(subPermissionName);
        }
        JsonArray subSubPermissionArray = subPermissionObject.getJsonArray("subPermissions");
        if (subSubPermissionArray == null) {
          continue;
        }
        for (Object subSubOb : subSubPermissionArray) {
          String subSubPermissionName = (String) subSubOb;
          if (!expandedPermissions.contains(subSubPermissionName)) {
            expandedPermissions.add(subSubPermissionName);
          }
        }
      }
    }
  }

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid,
      String tenant, String okapiUrl, String requestToken, String requestId,
      JsonArray permissions, String key) {
    logger.info("Retrieving permissions for userid "  + userid + " and expanding permissions");
    CacheEntry[] currentCache = new CacheEntry[1];
    boolean[] gotNewPerms = new boolean[1];
    boolean[] gotNewExpandedPerms = new boolean[1];
    gotNewPerms[0] = false;
    gotNewExpandedPerms[0] = false;
    if(cacheEntries) {
      if (key == null) {
        key = keyPrefix;
      }
      if (permissions != null && !key.endsWith(permissions.encode())) {
        key += permissions.encode();
      }
      logger.debug("Attempting to find cache with key of '{}'", key);
      currentCache[0] = cacheMap.getOrDefault(key, null);
      boolean found = true;
      if(currentCache[0] == null) {
        logger.debug("Cache not found");
        found = false;
      } else if((System.currentTimeMillis() - currentCache[0].getTimestamp()) / 1000 > 60 ) {
        logger.debug("Cache expired");
        found = false;
      }
      if(!found) {
        currentCache[0] = new CacheEntry();
        if(key != null) {
          cacheMap.put(key, currentCache[0]);
        }
      } else {
        logger.debug("Cache found");
      }
    }
    final String finalKey = key;
    Future<PermissionData> future = Future.future();
    Future<JsonArray> userPermsFuture;
    if(cacheEntries && currentCache[0].getPermissions() != null) {
      logger.debug("Using entry from cache for user permissions");
      userPermsFuture = Future.succeededFuture(currentCache[0].getPermissions());
    } else {
      logger.debug("Unable to find user permissions in cache, retrieving permissions for user");
      userPermsFuture = getPermissionsForUser(userid, tenant, okapiUrl, requestToken, requestId);
      gotNewPerms[0] = true;
    }
    Future<JsonArray> expandedPermsFuture;
    if(cacheEntries && currentCache[0].getExpandedPermissions() != null) {
      logger.debug("Using entry from cache for expanded permissions");
      expandedPermsFuture = Future.succeededFuture(currentCache[0].getExpandedPermissions());
    } else {
      logger.debug("No expanded permissions in cache, expanding permissions");
      expandedPermsFuture = expandPermissions(permissions, tenant, okapiUrl, requestToken, requestId);
      gotNewExpandedPerms[0] = true;
    }
    //final boolean updateCache = gotNewPerms;
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
          if( (gotNewPerms[0] && copiedUserPerms.size() > 0) ||
              (gotNewExpandedPerms[0] && copiedExpandedPerms.size() > 0)) {
            currentCache[0].setExpandedPermissions(copiedExpandedPerms);
                logger.debug("Setting populated cache with key of {}", finalKey);
            currentCache[0].resetTime();
          cacheMap.put(finalKey, currentCache[0]);
          }
        }
        future.complete(permissionData);
      }
    });
    return future;
  }

  @Override
  public void clearCache(String key) {
    if(cacheMap != null && cacheMap.containsKey(key)) {
        cacheMap.remove(key);
    }
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

  public void resetTime() {
    timestamp = System.currentTimeMillis();
  }
}
