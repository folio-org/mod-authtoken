package org.folio.auth.authtokenmodule.impl;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
  private static final Logger logger = LogManager.getLogger(ModulePermissionsSource.class);
  private final WebClient client;
  private final Map<String,CacheEntry<JsonArray>> expandPermissionsMap = new HashMap<>();
  private final Map<String,CacheEntry<JsonArray>> permissionsForUserMap = new HashMap<>();
  private static int expandPermissionsTimeout = 300;
  private static int permissionsForUserTimeout = 60;

  public ModulePermissionsSource(Vertx vertx, int timeout) {
    this.vertx = vertx;
    WebClientOptions options = new WebClientOptions();
    options.setConnectTimeout(timeout * 1000);
    options.setMaxPoolSize(100);
    client = WebClient.create(vertx, options);
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

    final String key = tenant + "_" + userId;
    CacheEntry<JsonArray> entry = permissionsForUserMap.get(key);
    if (entry != null && entry.getAge() < permissionsForUserTimeout) {
      return Future.succeededFuture(entry.getEntry());
    }
    Future<JsonArray> future = getPermissionsForUser(userId, tenant, okapiUrl, requestToken, requestId);
    return future.compose(res -> {
      permissionsForUserMap.put(key, new CacheEntry<>(res));
      return Future.succeededFuture(res);
    });
  }

  private Future<JsonArray> getPermissionsForUser(String userId, String tenant, String okapiUrl,
                                                  String requestToken, String requestId) {
    logger.debug("gerPermissionsForUser userid=" + userId);
    String permUserRequestUrl = okapiUrl + "/perms/users?query=userId==" + userId;
    logger.debug("Requesting permissions user object from URL at " + permUserRequestUrl);
    HttpRequest<Buffer> permUserReq = client.getAbs(permUserRequestUrl);
    setHeaders(permUserReq, requestToken, tenant, requestId);
    return permUserReq.send()
        .compose(permUserRes -> {
          if (permUserRes.statusCode() != 200) {
            String message = "Expected return code 200, got " + permUserRes.statusCode()
                + " : " + permUserRes.bodyAsString();
            logger.error(message);
            return Future.failedFuture(message);
          }
          JsonObject permUser = null;
          try {
            JsonObject permUserResults = permUserRes.bodyAsJsonObject();
            permUser = permUserResults.getJsonArray("permissionUsers").getJsonObject(0);
          } catch (Exception e) {
            logger.error(e.getMessage());
            return Future.failedFuture(e);
          }
          final String requestUrl = okapiUrl + "/perms/users/" + permUser.getString("id") + "/permissions?expanded=true";
          logger.debug("Requesting permissions from URL at {}", requestUrl);
          HttpRequest<Buffer> req = client.getAbs(requestUrl);
          setHeaders(req, requestToken, tenant, requestId);
          return req.send()
              .compose(res -> {
                if (res.statusCode() == 404) {
                  //In the event of a 404, that means that the permissions user
                  //doesn't exist, so we'll return an empty list to indicate no permissions
                  return Future.succeededFuture(new JsonArray());
                }
                if (res.statusCode() != 200) {
                  String failMessage = "Unable to retrieve permissions (code " + res.statusCode() + "): " + res.bodyAsString();
                  logger.debug(failMessage);
                  return Future.failedFuture(failMessage);
                }
                // 200
                JsonObject permissionsObject;
                try {
                  permissionsObject = res.bodyAsJsonObject();
                } catch (Exception e) {
                  logger.debug("Error parsing permissions object: " + e.getLocalizedMessage());
                  permissionsObject = null;
                }
                if (permissionsObject != null && permissionsObject.getJsonArray("permissionNames") != null) {
                  logger.debug("Got permissions");
                  return Future.succeededFuture(permissionsObject.getJsonArray("permissionNames"));
                } else {
                  logger.error("Got malformed/empty permissions object");
                  return Future.failedFuture("Got malformed/empty permissions object");
                }
              });
        });
  }

  private void setHeaders(HttpRequest<Buffer> req, String requestToken,
                          String tenant, String requestId) {
    if (requestId != null) {
      req.headers().add(MainVerticle.REQUESTID_HEADER, requestId);
    }
    req.headers()
        .add(MainVerticle.OKAPI_TOKEN_HEADER, requestToken)
        .add(MainVerticle.OKAPI_TENANT_HEADER, tenant)
        .add(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON)
        .add(MainVerticle.ACCEPT, MainVerticle.APPLICATION_JSON);
  }

  private Future<JsonArray> expandPermissionsCached(JsonArray permissions, String tenant, String okapiUrl,
                                                    String requestToken, String requestId) {
    final String key = tenant + "_" + permissions.encodePrettily();
    CacheEntry<JsonArray> entry = expandPermissionsMap.get(key);
    if (entry != null && entry.getAge() < expandPermissionsTimeout) {
      return Future.succeededFuture(entry.getEntry());
    }
    Future<JsonArray> future = expandPermissions(permissions, tenant, okapiUrl, requestToken, requestId);
    return future.compose(res -> {
      expandPermissionsMap.put(key, new CacheEntry<>(res));
      return Future.succeededFuture(res);
    });
  }

  public Future<JsonArray> expandPermissions(JsonArray permissions, String tenant,
                                             String okapiUrl, String requestToken, String requestId) {
    if (permissions.isEmpty()) {
      return Future.succeededFuture(new JsonArray());
    }
    logger.debug("Expanding permissions array");
    String query = "(";
    StringJoiner joiner = new StringJoiner(" or ");
    for (Object ob : permissions) {
      String permissionName = (String) ob;
      joiner.add("permissionName==\"" + permissionName + "\"");
    }
    query = query + joiner.toString() + ")";
    String requestUrl = okapiUrl + "/perms/permissions?"
        + "expanded=true&query=" + URLEncoder.encode(query, StandardCharsets.UTF_8);
    logger.debug("Requesting expanded permissions from URL at {}", requestUrl);
    HttpRequest<Buffer> req = client.getAbs(requestUrl);
    setHeaders(req, requestToken, tenant, requestId);
    return req.send().compose(res -> handleExpandPermissions(res, res.bodyAsBuffer(), permissions));
  }

  private Future<JsonArray> handleExpandPermissions(HttpResponse<Buffer> res, Buffer body,
                                                    JsonArray permissions) {

    if (res.statusCode() != 200) {
      String message = "Expected 200, got result " + res.statusCode()
          + " : " + body.toString();
      logger.error("Error expanding " + permissions.encode() + ": " + message);
      return Future.failedFuture(message);
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
    return Future.succeededFuture(expandedPermissions);
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
  public Future<PermissionData> getUserAndExpandedPermissions(
      String userid, String tenant, String okapiUrl, String requestToken, String requestId,
      JsonArray permissions) {

    logger.debug("Retrieving permissions for userid " + userid + " and expanding permissions");
    Future<JsonArray> userPermsFuture
        = getPermissionsForUserCached(userid, tenant, okapiUrl, requestToken, requestId);
    Future<JsonArray> expandedPermsFuture
        = expandPermissionsCached(permissions, tenant, okapiUrl, requestToken, requestId);
    CompositeFuture compositeFuture = CompositeFuture.all(userPermsFuture, expandedPermsFuture);
    return compositeFuture.compose(compositeRes -> {
      PermissionData permissionData = new PermissionData();
      permissionData.setUserPermissions(userPermsFuture.result());
      permissionData.setExpandedPermissions(expandedPermsFuture.result());
      return Future.succeededFuture(permissionData);
    });
  }
}
