package org.folio.auth.authtokenmodule;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import com.nimbusds.jose.JOSEException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import org.junit.runner.RunWith;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

@RunWith(VertxUnitRunner.class)
public class UserServiceTest {

  private static final String TENANT = "test-tenant";
  private static final String TOKEN = "test-token";
  private static final String REQ_ID = "test-req-id";

  private static int mockPort;
  private static int freePort;
  private static String mockUrl;
  private static String badMockUrl;
  private static Vertx vertx;

  @BeforeClass
  public static void setUpClass(TestContext context) throws NoSuchAlgorithmException, JOSEException, ParseException {

    Async async = context.async();

    freePort = NetworkUtils.nextFreePort();
    mockPort = NetworkUtils.nextFreePort();
    mockUrl = "http://localhost:" + mockPort;
    badMockUrl = "http://localhost:" + freePort;
    vertx = Vertx.vertx();

    DeploymentOptions mockOptions = new DeploymentOptions().setConfig(new JsonObject().put("port", mockPort));
    vertx.deployVerticle(UsersMock.class.getName(), mockOptions, mockRes -> {
      if (mockRes.failed()) {
        mockRes.cause().printStackTrace();
        context.fail(mockRes.cause());
      }
      async.complete();
    });
  }

  @AfterClass
  public static void tearDownClass(TestContext context) {
    Async async = context.async();
    vertx.close(x -> {
      async.complete();
    });
  }

  @Test
  public void testNonExistingUser(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("0", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.succeeded()) {
        context.fail("User id 0 should fail with 404 response");
      }
      async.complete();
    });
  }

  @Test
  public void testInvalidResponseCode(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("00", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.succeeded()) {
        context.fail("User id 00 should fail with invalid response code");
      }
      context.assertTrue(ar.cause().getLocalizedMessage().contains("response code"));
      async.complete();
    });
  }

  @Test
  public void testInvalidResponseJson(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("000", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.succeeded()) {
        context.fail("User id 000 should fail with invalid user response");
      }
      context.assertTrue(ar.cause().getLocalizedMessage().contains("Invalid user response"));
      async.complete();
    });
  }

  @Test
  public void testNullActive(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("1", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || ar.result() != null) {
        context.fail("User id 1 should be null");
      }
      context.assertNull(ar.result());
      async.complete();
    });
  }

  @Test
  public void testInactiveUser(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("2", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || ar.result().booleanValue()) {
        context.fail("User id 2 should be inactive");
      }
      context.assertFalse(ar.result());
      async.complete();
    });
  }

  @Test
  public void testActiveUser(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("3", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result().booleanValue()) {
        context.fail("User id 3 should be active");
      }
      context.assertTrue(ar.result());
      async.complete();
    });
  }

  @Test
  public void testMultipleActiveUsers(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("3", TENANT, mockUrl, "token", "reqId").onComplete(ar -> {
      if (ar.failed() || !ar.result().booleanValue()) {
        context.fail("User id 3 should be active");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(1000, id -> {
      userService.isActiveUser("33", TENANT, mockUrl, "token", null).onComplete(ar -> {
        if (ar.failed() || !ar.result().booleanValue()) {
          context.fail("User id 33 should be active");
        }
        context.assertTrue(ar.result());
        async.complete();
      });
    });
  }

  @Test
  public void testCache(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isActiveUser("4", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result().booleanValue()) {
        context.fail("User id 4 should be active");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(1000, id -> {
      userService.isActiveUser("4", TENANT, badMockUrl, TOKEN, REQ_ID).onComplete(ar -> {
        if (ar.failed() || !ar.result().booleanValue()) {
          context.fail("User id 4 should be active");
        }
        context.assertTrue(ar.result());
        async.complete();
      });
    });
  }

  @Test
  public void testExpiredCache(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 1, 10);
    userService.isActiveUser("4", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result().booleanValue()) {
        context.fail("User id 4 should be active");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(2000, id -> {
      userService.isActiveUser("4", TENANT, "http://localhost:" + freePort, "", "").onComplete(ar -> {
        if (ar.succeeded()) {
          context.fail("Expired cache should make a new request");
        }
        async.complete();
      });
    });
  }

  @Test
  public void testPurgeCache(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 10, 1);
    userService.isActiveUser("4", TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result().booleanValue()) {
        context.fail("User id 4 should be active");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(2000, id -> {
      userService.isActiveUser("4", TENANT, "http://localhost:" + freePort, "", "").onComplete(ar -> {
        if (ar.succeeded()) {
          context.fail("Purged cache should make a new request");
        }
        async.complete();
      });
    });
  }

  @Test
  public void testUserTenantInvalidResponseCode(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isUserTenantNotEmpty("00", mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.succeeded()) {
        context.fail("User tenants 00 should fail with invalid response code");
      }
      context.assertTrue(ar.cause().getLocalizedMessage().contains("response code"));
      async.complete();
    });
  }

  @Test
  public void testUserTenantInvalidResponseJson(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isUserTenantNotEmpty("000", mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.succeeded()) {
        context.fail("User tenants  000 should fail with invalid user response");
      }
      context.assertTrue(ar.cause().getLocalizedMessage().contains("Invalid user-tenants response"));
      async.complete();
    });
  }

  @Test
  public void testUserTenantNotEmpty(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isUserTenantNotEmpty("test-tenant-1", mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result()) {
        context.fail("User tenant should not be empty");
      }
      context.assertTrue(ar.result());
      async.complete();
    });
  }

  @Test
  public void testUserTenantEmpty(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isUserTenantNotEmpty(TENANT, mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || ar.result()) {
        context.fail("User tenant should be empty");
      }
      context.assertFalse(ar.result());
      async.complete();
    });
  }

  @Test
  public void testUserTenantCacheHit(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 3, 10);
    userService.isUserTenantNotEmpty("test-tenant-1", mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result()) {
        context.fail("User tenant should not be empty");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(1000, id -> {
      userService.isUserTenantNotEmpty("test-tenant-1", "http://localhost:" + freePort, "", "").onComplete(ar -> {
        if (ar.failed() || !ar.result()) {
          context.fail("User tenant should not be empty");
        }
        context.assertTrue(ar.result());
        async.complete();
      });
    });
  }

  @Test
  public void testUserTenantCacheExpired(TestContext context) {
    Async async = context.async();
    UserService userService = new UserService(vertx, 1, 10);
    userService.isUserTenantNotEmpty("test-tenant-1", mockUrl, TOKEN, REQ_ID).onComplete(ar -> {
      if (ar.failed() || !ar.result()) {
        context.fail("User tenant should not be empty");
      }
      context.assertTrue(ar.result());
    });
    vertx.setTimer(2000, id -> {
      userService.isUserTenantNotEmpty("test-tenant-1", "http://localhost:" + freePort, "", "").onComplete(ar -> {
        if (ar.failed()) {
          context.fail("User tenant cache should not expire");
        }
        context.assertTrue(ar.result());
        async.complete();
      });
    });
  }

}
