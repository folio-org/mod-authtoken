package org.folio.auth.authtokenmodule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;
import static org.folio.auth.authtokenmodule.PermService.SYS_PERM_PREFIX;
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

  private static final String SYS_PERM = SYS_PERM_PREFIX + "1";
  private static final String SUB_PERM_1 = "user.read";
  private static final String SUB_PERM_2 = "user.write";
  
  private static final String SYS_PERM_2 = SYS_PERM_PREFIX + "2";
  private static final String SYS_PERM_EMPTY = SYS_PERM_PREFIX + "Empty";

  private static Vertx vertx;
  private static ModulePermissionsSource mps;
  private static PermService permService;

  @BeforeClass
  public static void setup() {
    vertx = Vertx.vertx();
    mps = mock(ModulePermissionsSource.class);
    JsonArray perms = new JsonArray().add(SYS_PERM).add(SUB_PERM_1).add(SUB_PERM_2);
    when(mps.expandPermissions(any(), any(), any(), any(), any()))
      .thenReturn(Future.succeededFuture(perms));
    permService = new PermService(vertx, mps, 2, 2);
  }

  @Test
  public void testExpandPermissions(TestContext context) {
    Async async = context.async();
    JsonArray perms = new JsonArray().add(SYS_PERM);
    JsonArray rs = PermService.expandSystemPermissionsUsingCache(perms);
    // no static cache
    assertEquals(1, rs.size());
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
    when(badMps.expandPermissions(any(), any(), any(), any(), any()))
        .thenReturn(Future.failedFuture("test failure"));
    PermService ps = new PermService(vertx, badMps, 10, 10);
    Future<JsonArray> rs = ps.expandSystemPermissions(new JsonArray()
      .add(SYS_PERM_2), "a", "a", "a", "a");
    assertTrue(rs.failed());
  }

  @Test
  public void testEmptySystemPerm() throws InterruptedException {
    ModulePermissionsSource emptyMps = mock(ModulePermissionsSource.class);
    when(emptyMps.expandPermissions(any(), any(), any(), any(), any()))
        .thenReturn(Future.succeededFuture(new JsonArray().add(SYS_PERM_EMPTY)))
        .thenReturn(Future.succeededFuture(new JsonArray().add(SYS_PERM_EMPTY)));
    PermService ps = new PermService(vertx, emptyMps, 10, 10);
    Future<JsonArray> rs = ps.expandSystemPermissions(new JsonArray()
      .add(SYS_PERM_EMPTY), "a", "a", "a", "a");
    assertTrue(rs.result().isEmpty());
    rs = ps.expandSystemPermissions(new JsonArray().add(SYS_PERM_EMPTY), "a", "a", "a", "a");
    assertTrue(rs.result().isEmpty());
    verify(emptyMps, times(2)).expandPermissions(any(), any(), any(), any(), any());
  }

  private JsonArray callExpandPerms(JsonArray perms) {
    return permService.expandSystemPermissions(perms, "a", "a", "a", "a").result();
  }

  private void verifyExpandPerms(JsonArray rs) {
    assertEquals(2, rs.size());
    assertTrue(rs.contains(SUB_PERM_1));
    assertTrue(rs.contains(SUB_PERM_2));
  }
}
