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
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;
import org.folio.auth.authtokenmodule.CacheEntry;
import org.folio.auth.authtokenmodule.MainVerticle;
import org.folio.auth.authtokenmodule.PermissionData;
import org.folio.auth.authtokenmodule.PermissionsSource;

/**
 *
 * @author kurt
 */

public class ModulePermissionsSource implements PermissionsSource {

  private Vertx vertx;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  private final HttpClient client;
  private final Map<String,CacheEntry<JsonArray>> expandPermissionsMap = new HashMap<>();
  private final Map<String,CacheEntry<JsonArray>> permissionsForUserMap = new HashMap<>();
  private static int expandPermissionsTimeout = 300;
  private static int permissionsForUserTimeout = 60;

  public ModulePermissionsSource(Vertx vertx, int timeout) {
    this.vertx = vertx;
    HttpClientOptions options = new HttpClientOptions();
    options.setConnectTimeout(timeout * 1000);
    options.setMaxPoolSize(100);
    client = vertx.createHttpClient(options);
  }

  @Override
  public void clearCache() {
    expandPermissionsMap.clear();
    permissionsForUserMap.clear();
  }

  public static void setCacheTimeout(int sec) {
    expandPermissionsTimeout = permissionsForUserTimeout = sec;
  }

  private Future<JsonArray> getPermissionsForUserCached(String userId, String tenant,
    String okapiUrl, String requestToken, String requestId) {

    Future<JsonArray> future = Future.future();
    final String key = tenant + "_" + userId;
    CacheEntry<JsonArray> entry = permissionsForUserMap.get(key);
    if (entry != null && entry.getAge() < permissionsForUserTimeout) {
      future.complete(entry.getEntry());
      return future;
    }
    future = getPermissionsForUser(userId, tenant, okapiUrl, requestToken, requestId);
    return future.compose(res -> {
      permissionsForUserMap.put(key, new CacheEntry<>(res));
      Future<JsonArray> future2 = Future.future();
      future2.complete(res);
      return future2;
    });
  }

  private Future<JsonArray> getPermissionsForUser(String userId, String tenant, String okapiUrl,
    String requestToken, String requestId) {
    logger.debug("gerPermissionsForUser userid=" + userId);
    Future<JsonArray> future = Future.future();
    String permUserRequestUrl = okapiUrl + "/perms/users?query=userId==" + userId;
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
    permUserReq.exceptionHandler(future::fail);
    endRequest(permUserReq, requestToken, tenant, requestId);
    return future;
  }

  private void endRequest(HttpClientRequest req, String requestToken,
    String tenant, String requestId) {
    if (requestId != null) {
      req.headers().add(MainVerticle.REQUESTID_HEADER, requestId);
    }
    req.headers()
      .add(MainVerticle.OKAPI_TOKEN_HEADER, requestToken)
      .add(MainVerticle.OKAPI_TENANT_HEADER, tenant)
      .add(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON)
      .add(MainVerticle.ACCEPT, MainVerticle.APPLICATION_JSON);
    req.end();
  }

  public Future<JsonArray> expandPermissionsCached(JsonArray permissions,
    String tenant, String okapiUrl, String requestToken, String requestId) {

    final String key = tenant + "_" + permissions.encodePrettily();
    Future<JsonArray> future = Future.future();
    CacheEntry<JsonArray> entry = expandPermissionsMap.get(key);
    if (entry != null && entry.getAge() < expandPermissionsTimeout) {
      future.complete(entry.getEntry());
      return future;
    }
    future = expandPermissions(permissions, tenant, okapiUrl, requestToken, requestId);
    return future.compose(res -> {
      Future<JsonArray> future2 = Future.future();
      expandPermissionsMap.put(key, new CacheEntry<>(res));
      future2.complete(res);
      return future2;
    });
  }

  private Future<JsonArray> expandPermissions(JsonArray permissions, String tenant,
    String okapiUrl, String requestToken, String requestId) {
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
      joiner.add("permissionName==\"" + permissionName + "\"");
    }
    query = query + joiner.toString() + ")";
    try {
      String requestUrl = okapiUrl + "/perms/permissions?"
        + "expanded=true&query=" + URLEncoder.encode(query, "UTF-8");
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

  @Override
  public Future<PermissionData> getUserAndExpandedPermissions(String userid,
    String tenant, String okapiUrl, String requestToken, String requestId,
    JsonArray permissions) {
    logger.debug("Retrieving permissions for userid " + userid + " and expanding permissions");

    Future<JsonArray> userPermsFuture
      = getPermissionsForUserCached(userid, tenant, okapiUrl, requestToken, requestId);
    Future<JsonArray> expandedPermsFuture
      = expandPermissionsCached(permissions, tenant, okapiUrl, requestToken, requestId);
    Future<PermissionData> future = Future.future();
    CompositeFuture compositeFuture = CompositeFuture.all(userPermsFuture, expandedPermsFuture);
    compositeFuture.setHandler(compositeRes -> {
      if (compositeFuture.failed()) {
        future.fail(compositeFuture.cause());
      } else {
        PermissionData permissionData = new PermissionData();
        permissionData.setUserPermissions(userPermsFuture.result());
        permissionData.setExpandedPermissions(expandedPermsFuture.result());
        future.complete(permissionData);
      }
    });
    return future;
  }
}
