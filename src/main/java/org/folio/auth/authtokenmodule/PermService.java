package org.folio.auth.authtokenmodule;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;

/**
 * Help to expand system generated module permission set to the actual permissions.
 */
public class PermService {

  private static final Logger logger = LoggerFactory.getLogger(PermService.class);
  // map from system generated module permission set name to the actual permissions
  private static ConcurrentMap<String, PermEntry> cache = new ConcurrentHashMap<>();
  private ModulePermissionsSource modulePermissionsSource;
  private long cachePeriod;

  public PermService(Vertx vertx, ModulePermissionsSource modulePermissionsSource,
      int cacheInSeconds, int purgeCacheInSeconds) {
    this.modulePermissionsSource = modulePermissionsSource;

    // purge less used cache entry periodically
    cachePeriod = cacheInSeconds * 1000L;
    vertx.setPeriodic(purgeCacheInSeconds * 1000L, id -> {
      logger.info("Purge system permission set cache");
      Set<String> keys = new HashSet<>(cache.keySet());
      for (String key : keys) {
        if ((System.currentTimeMillis() - cache.get(key).getTimestamp()) > cachePeriod) {
          cache.remove(key);
          logger.info("Removed cache of system permission: " + key);
        }
      }
    });
  }

  /**
   * Expand system permissions using cache. If not cached, return as is.
   *
   * @param permissions
   * @return original permissions plus sub permissions
   */
  public static JsonArray expandSystemPermissionsUsingCache(JsonArray permissions) {
    JsonArray perms = new JsonArray().addAll(permissions);
    for (int i = 0, n = permissions.size(); i < n; i++) {
      PermEntry entry = cache.get(permissions.getString(i));
      if (entry != null) {
        entry.updateTimestamp();
        perms.addAll(entry.getPerms());
      }
    }
    return perms;
  }

  /**
   * Expand system permissions.
   *
   * @param permissions
   * @param tenant
   * @param okapiUrl
   * @param requestToken
   * @param requestId
   * @return
   */
  public Future<JsonArray> expandSystemPermissions(JsonArray permissions, String tenant,
      String okapiUrl, String requestToken, String requestId) {
    Future<JsonArray> future = Future.future();
    JsonArray expandedPerms = new JsonArray().addAll(permissions);
    @SuppressWarnings("rawtypes")
    List<Future> futures = new ArrayList<>();
    for (int i = 0, n = permissions.size(); i < n; i++) {
      String perm = permissions.getString(i);
      if (!perm.startsWith("SYS#")) {
        continue;
      }
      PermEntry entry = cache.get(perm);
      if (entry != null) {
        entry.updateTimestamp();
        expandedPerms.addAll(entry.getPerms());
        continue;
      }
      futures.add(modulePermissionsSource.expandPermissionsCached(new JsonArray().add(perm), tenant,
          okapiUrl, requestToken, requestId));
    }
    CompositeFuture.join(futures).setHandler(ar -> {
      if (ar.succeeded()) {
        futures.forEach(f -> {
          JsonArray perms = (JsonArray) f.result();
          String perm = perms.getString(0);
          perms.remove(0);
          cache.put(perm, new PermEntry(perms));
          expandedPerms.addAll(perms);
        });
        future.complete(expandedPerms);
      } else {
        future.fail(ar.cause());
        logger.error("Failed to expand permissions", ar.cause());
      }
    });
    return future;
  }

  private static class PermEntry {
    private long timestamp = System.currentTimeMillis();

    private JsonArray perms = new JsonArray();

    public PermEntry(JsonArray perms) {
      this.perms = perms;
    }

    public long getTimestamp() {
      return timestamp;
    }

    public JsonArray getPerms() {
      return perms;
    }

    public void updateTimestamp() {
      timestamp = System.currentTimeMillis();
    }
  }

}
