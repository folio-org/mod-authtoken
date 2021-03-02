package org.folio.auth.authtokenmodule;

import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;

/**
 * Help to expand system generated module permission set to the actual
 * permissions.
 */
public class PermService {

  public static final String SYS_PERM_PREFIX = "SYS#";

  private static final Logger logger = LogManager.getLogger(PermService.class);

  // map from system generated module permission set name to the actual permissions
  private static final ConcurrentMap<String, PermEntry> cache = new ConcurrentHashMap<>();
  private final ModulePermissionsSource modulePermissionsSource;
  private final long cachePeriod;

  public PermService(Vertx vertx, ModulePermissionsSource modulePermissionsSource, int cacheInSeconds,
      int purgeCacheInSeconds) {
    this.modulePermissionsSource = modulePermissionsSource;

    // purge less used cache entry periodically
    cachePeriod = cacheInSeconds * 1000L;
    vertx.setPeriodic(purgeCacheInSeconds * 1000L, id -> {
      logger.info("Purge system permission set cache");
      Set<String> keys = new HashSet<>(cache.keySet());
      for (String key : keys) {
        if ((System.currentTimeMillis() - cache.get(key).getTimestamp()) > cachePeriod) {
          cache.remove(key);
          logger.info("Removed cache of system permission: {}", key);
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
    JsonArray expandedPerms = new JsonArray();
    for (int i = 0, n = permissions.size(); i < n; i++) {
      String perm = permissions.getString(i);
      PermEntry entry = cache.get(perm);
      if (entry != null) {
        expandedPerms.addAll(entry.getPerms());
        entry.updateTimestamp();
      } else {
        expandedPerms.add(perm);
      }
    }
    logger.debug("Expand using static cache from {} to {}", permissions, expandedPerms);
    return expandedPerms;
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
  @SuppressWarnings("java:S3740")
  public Future<JsonArray> expandSystemPermissions(JsonArray permissions, String tenant, String okapiUrl,
                                                   String requestToken, String requestId) {
    JsonArray expandedPerms = new JsonArray();
    @SuppressWarnings("rawtypes")
    List<Future> futures = new ArrayList<>();
    for (int i = 0, n = permissions.size(); i < n; i++) {
      String perm = permissions.getString(i);
      if (!perm.startsWith(SYS_PERM_PREFIX)) {
        expandedPerms.add(perm);
        continue;
      }
      PermEntry entry = cache.get(perm);
      if (entry != null && !entry.getPerms().isEmpty()) {
        expandedPerms.addAll(entry.getPerms());
        entry.updateTimestamp();
      } else {
        futures.add(modulePermissionsSource.expandPermissions(new JsonArray().add(perm), tenant, okapiUrl,
            requestToken, requestId));
      }
    }
    return CompositeFuture.join(futures).compose(ar -> {
      futures.forEach(f -> {
        JsonArray perms = (JsonArray) f.result();
        String perm = perms.getString(0);
        perms.remove(0);
        cache.put(perm, new PermEntry(perms));
        expandedPerms.addAll(perms);
      });
      logger.debug("Expand from {} to {}", permissions, expandedPerms);
      return Future.succeededFuture(expandedPerms);
    });
  }

  private static class PermEntry {
    private long timestamp = System.currentTimeMillis();

    private final JsonArray perms;

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
