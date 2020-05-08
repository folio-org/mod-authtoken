package org.folio.auth.authtokenmodule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import org.junit.runner.RunWith;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.junit.BeforeClass;
import org.junit.Test;

@RunWith(VertxUnitRunner.class)
public class PermServiceTest {

  private static final String SYS_PERM = "SYS#1";
  private static final String SUB_PERM_1 = "user.read";
  private static final String SUB_PERM_2 = "user.write";

  private static Vertx vertx;
  private static ModulePermissionsSource mps;
  private static PermService permService;

  @BeforeClass
  public static void setup() {
    vertx = Vertx.vertx();
    mps = mock(ModulePermissionsSource.class);
    JsonArray perms = new JsonArray().add(SYS_PERM).add(SUB_PERM_1).add(SUB_PERM_2);
    when(mps.expandPermissionsCached(any(), any(), any(), any(), any()))
        .thenReturn(Future.succeededFuture(perms));
    permService = new PermService(vertx, mps, 2, 2);
  }

  @Test
  public void testExpandPermissions(TestContext context) {
    Async async = context.async();
    JsonArray perms = new JsonArray().add(SYS_PERM);
    JsonArray rs = PermService.expandSystemPermissionsUsingCache(perms);
    // no static cache
    assertTrue(rs.size() == 1);
    assertTrue(rs.contains(SYS_PERM));
    // no cache
    rs = callExpandPerms(perms);
    verifyExpandPerms(rs);
    // use cache
    rs = callExpandPerms(perms);
    verifyExpandPerms(rs);
    // has static cache
    rs = PermService.expandSystemPermissionsUsingCache(perms);
    verifyExpandPerms(rs);
    // test cache purge
    vertx.setTimer(4000, id -> {
      JsonArray ja = PermService.expandSystemPermissionsUsingCache(perms);
      context.assertEquals(1, ja.size());
      async.complete();
    });
  }

  @Test
  public void testExpandNonSystemPerm() {
    String perm = "test.read";
    JsonArray rs = callExpandPerms(new JsonArray().add(perm));
    assertEquals(1, rs.size());
    assertTrue(rs.contains(perm));
  }

  @Test
  public void testFailedFuture() throws InterruptedException {
    ModulePermissionsSource badMps = mock(ModulePermissionsSource.class);
    when(badMps.expandPermissionsCached(any(), any(), any(), any(), any()))
        .thenReturn(Future.failedFuture("test failure"));
    PermService ps = new PermService(vertx, badMps, 10, 10);
    Future<JsonArray> rs =
        ps.expandSystemPermissions(new JsonArray().add("SYS#2"), "a", "a", "a", "a");
    assertTrue(rs.failed());
  }

  private JsonArray callExpandPerms(JsonArray perms) {
    return permService.expandSystemPermissions(perms, "a", "a", "a", "a").result();
  }

  private void verifyExpandPerms(JsonArray rs) {
    assertEquals(3, rs.size());
    assertTrue(rs.contains(SYS_PERM));
    assertTrue(rs.contains(SUB_PERM_1));
    assertTrue(rs.contains(SUB_PERM_2));
  }
}
