package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.WebClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.okapi.common.XOkapiHeaders;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class UserService {

  private static final Logger logger = LogManager.getLogger(PermService.class);

  // map from tenant id to user id and then to user active or not
  private ConcurrentMap<String, Boolean> userTenantCache = new ConcurrentHashMap<>();
  private ConcurrentMap<String, ConcurrentMap<String, UserEntry>> activeUserCache = new ConcurrentHashMap<>();

  private final WebClient client;
  private final long cachePeriod;

  public UserService(Vertx vertx, int cacheInSeconds, int purgeCacheInSeconds) {
    client = WebClient.create(vertx);
    cachePeriod = cacheInSeconds * 1000L;

    // purge cache periodically
    vertx.setPeriodic(purgeCacheInSeconds * 1000L, id -> {
      activeUserCache = new ConcurrentHashMap<>();
      userTenantCache = new ConcurrentHashMap<>();
    });
  }

  /**
   * Return if user is active or not
   *
   * @param userId
   * @param tenant
   * @param okapiUrl
   * @param requestToken
   * @param requestId
   *
   * @return true or false in {@link Future}
   */
  public Future<Boolean> isActiveUser(String userId, String tenant, String okapiUrl,
      String requestToken, String requestId) {

    Map<String, UserEntry> map = activeUserCache.get(tenant);
    if (map == null) {
      return isActiveUserNoCache(userId, tenant, okapiUrl, requestToken, requestId);
    }
    UserEntry entry = map.get(userId);
    if (entry == null) {
      return isActiveUserNoCache(userId, tenant, okapiUrl, requestToken, requestId);
    }
    if (isExpired(entry.getTimestamp())) {
      return isActiveUserNoCache(userId, tenant, okapiUrl, requestToken, requestId);
    }
    return Future.succeededFuture(entry.getActive());
  }

  private Future<Boolean> isActiveUserNoCache(String userId, String tenant, String okapiUrl,
                                              String requestToken, String requestId) {

    HttpRequest<Buffer> req = client.getAbs(okapiUrl + "/users/" + userId);

    req.headers().add(XOkapiHeaders.TOKEN, requestToken)
        .add(XOkapiHeaders.TENANT, tenant)
        .add(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON)
        .add(MainVerticle.ACCEPT, MainVerticle.APPLICATION_JSON);
    if (requestId != null) {
      req.headers().add(XOkapiHeaders.REQUEST_ID, requestId);
    }
    return req.send()
        .compose(res -> {
          if (res.statusCode() == 200) {
            Boolean active;
            try {
              active = res.bodyAsJsonObject().getBoolean("active");
            } catch (Exception e) {
              String msg = "Invalid user response: " + res.bodyAsString() + " for id " + userId;
              logger.warn(msg, e);
              return Future.failedFuture(new UserServiceException(msg, e));
            }
            ConcurrentMap<String, UserEntry> newMap = new ConcurrentHashMap<>();
            ConcurrentMap<String, UserEntry> oldMap = activeUserCache.putIfAbsent(tenant, newMap);
            ConcurrentMap<String, UserEntry> map = oldMap == null ? newMap : oldMap;
            map.put(userId, new UserEntry(active));
            return Future.succeededFuture(active);
          }
          if (res.statusCode() == 404) {
            return Future.failedFuture(new UserServiceException("User with id " + userId + " does not exist"));
          }
          return Future.failedFuture(new UserServiceException(
              "Unexpected user response code " + res.statusCode() + " for user id " + userId));
        });
  }

  public Future<Boolean> isUserTenantNotEmpty(String tenant, String okapiUrl,
                                              String requestToken, String requestId) {
    Boolean value = userTenantCache.get(tenant);
    if (value == null) {
      return isUserTenantNotEmptyNoCache(tenant, okapiUrl, requestToken, requestId);
    }
    return Future.succeededFuture(value);
  }

  private Future<Boolean> isUserTenantNotEmptyNoCache(String tenant, String okapiUrl,
                                              String requestToken, String requestId) {

    HttpRequest<Buffer> req = client.getAbs(okapiUrl + "/user-tenants?limit=1");

    req.headers().add(XOkapiHeaders.TOKEN, requestToken)
      .add(XOkapiHeaders.TENANT, tenant)
      .add(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON)
      .add(MainVerticle.ACCEPT, MainVerticle.APPLICATION_JSON);
    if (requestId != null) {
      req.headers().add(XOkapiHeaders.REQUEST_ID, requestId);
    }
    return req.send()
      .compose(res -> {
        if (res.statusCode() == 200) {
          Integer totalRecords;
          try {
            totalRecords = res.bodyAsJsonObject().getInteger("totalRecords");
          } catch (Exception e) {
            String msg = "Invalid user-tenants response";
            logger.warn(msg, e);
            return Future.failedFuture(new UserServiceException(msg, e));
          }
          boolean isNotEmpty = totalRecords > 0;
          userTenantCache.put(tenant, isNotEmpty);
          return Future.succeededFuture(isNotEmpty);
        }
        return Future.failedFuture(
          new UserServiceException("Unexpected response code from /user-tenants response code " + res.statusCode()));
      });
  }

  public static class UserServiceException extends Exception {

    private static final long serialVersionUID = -3210420712641520123L;

    public UserServiceException(String msg) {
      super(msg);
    }

    public UserServiceException(String msg, Throwable t) {
      super(msg, t);
    }

  }

  private static class UserEntry {
    private final long timestamp = System.currentTimeMillis();
    private final Boolean active;

    public UserEntry(Boolean active) {
      this.active = active;
    }

    public long getTimestamp() {
      return timestamp;
    }

    public Boolean getActive() {
      return active;
    }
  }

  private boolean isExpired(long timestamp) {
    return (System.currentTimeMillis() - timestamp) > cachePeriod;
  }

}
