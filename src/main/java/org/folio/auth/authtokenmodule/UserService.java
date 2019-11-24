package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class UserService {

  private final Logger logger = LoggerFactory.getLogger(UserService.class);

  // map from tenant id to user id and then to user active or not
  private ConcurrentMap<String, ConcurrentMap<String, UserEntry>> cache = new ConcurrentHashMap<>();

  private HttpClient client;
  private long cachePeriod;

  public UserService(Vertx vertx, int cacheInSeconds, int purgeCacheInSeconds) {
    client = vertx.createHttpClient();
    cachePeriod = cacheInSeconds * 1000L;

    // purge cache periodically
    vertx.setPeriodic(purgeCacheInSeconds * 1000, id -> {
      cache = new ConcurrentHashMap<>();
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

    Map<String, UserEntry> map = cache.get(tenant);
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

    Future<Boolean> future = Future.future();
    HttpClientRequest req = client.getAbs(okapiUrl + "/users/" + userId, res -> {
      res.exceptionHandler(e -> {
        String msg = "Unexpected response exception for user id " + userId;
        logger.warn(msg, e);
        future.fail(new UserServiceException(msg, e));
      });
      if (res.statusCode() == 200) {
        res.bodyHandler(user -> {
          Boolean active = null;
          try {
            active = new JsonObject(user.toString()).getBoolean("active");
          } catch (Exception e) {
            String msg = "Invalid user response: " + user + " for id " + userId;
            logger.warn(msg, e);
            future.fail(new UserServiceException(msg, e));
            return;
          }
          ConcurrentMap<String, UserEntry> newMap = new ConcurrentHashMap<>();
          ConcurrentMap<String, UserEntry> oldMap = cache.putIfAbsent(tenant, newMap);
          ConcurrentMap<String, UserEntry> map = oldMap == null ? newMap : oldMap;
          map.put(userId, new UserEntry(active));
          future.complete(active);
        });
        return;
      }
      if (res.statusCode() == 404) {
        future.fail(new UserServiceException("User with id " + userId + " does not exist"));
        return;
      }
      future.fail(new UserServiceException(
          "Unexpected user response code " + res.statusCode() + " for user id " + userId));
    });
    req.exceptionHandler(e -> {
      String msg = "Unexpected request exception for user id " + userId;
      logger.warn(msg, e);
      future.fail(new UserServiceException(msg, e));
    });

    req.headers().add(MainVerticle.OKAPI_TOKEN_HEADER, requestToken)
        .add(MainVerticle.OKAPI_TENANT_HEADER, tenant)
        .add(MainVerticle.CONTENT_TYPE, MainVerticle.APPLICATION_JSON)
        .add(MainVerticle.ACCEPT, MainVerticle.APPLICATION_JSON);
    if (requestId != null) {
      req.headers().add(MainVerticle.REQUESTID_HEADER, requestId);
    }
    req.end();
    return future;
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
    private long timestamp = System.currentTimeMillis();
    private Boolean active;

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
