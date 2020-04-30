package org.folio.auth.authtokenmodule;

import io.vertx.core.json.JsonArray;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ModPermCache {

  private static final Logger logger = LoggerFactory.getLogger(ModPermCache.class);

  // map from tenant id to modPermId and then to module permissions
  private static ConcurrentMap<String, ConcurrentMap<String, JsonArray>> cache =
      new ConcurrentHashMap<>();

  public static JsonArray get(String tenantId, String modPermId) {
    logger.error("get module permissions for " + tenantId + " and " + modPermId);
    return cache.get(tenantId).get(modPermId);
  }

  public static void put(String tenantId, String modPermId, JsonArray modulePermissions) {
    logger.error("put module permissions for " + tenantId + " and " + modPermId + " and "
        + modulePermissions.toString());
    cache.putIfAbsent(tenantId, new ConcurrentHashMap<>());
    cache.get(tenantId).putIfAbsent(modPermId, modulePermissions);
  }
}
