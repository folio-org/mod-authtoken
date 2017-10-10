package org.folio.auth.authtoken_module;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import com.jayway.restassured.RestAssured;
import static com.jayway.restassured.RestAssured.*;
import static org.hamcrest.Matchers.*;
import com.jayway.restassured.response.Response;
import guru.nidi.ramltester.restassured.RestAssuredClient;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.runner.RunWith;
import org.junit.Before;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;



/**
 *
 * @author heikki
 */
@RunWith(VertxUnitRunner.class)
public class AuthTokenTest {
  private static final Logger logger = LoggerFactory.getLogger("okapi");
  private static final String LS = System.lineSeparator();
  private static final String tenant = "Roskilde";
  private static HttpClient httpClient;
  private static TokenCreator tokenCreator;
  private static JsonObject payload;
  private static JsonObject payload2;
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String basicToken;
  private static String basicToken2;
  static int port;
  static int mockPort;
  static Vertx vertx;
  Async async;

  @BeforeClass
  public static void setUpClass(TestContext context) {
    Async async = context.async();
    port = nextFreePort();
    mockPort = nextFreePort();
    vertx = Vertx.vertx();

    logger.info("Setting up AuthTokenTest. Port=" + port);
    JsonObject conf = new JsonObject()
      .put("port", Integer.toString(port));
    DeploymentOptions opt = new DeploymentOptions()
      .setConfig(conf);
    payload = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("dummy", true)
      .put("sub", "jones");
    payload2 = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("sub", "jones");     
    tokenCreator = new TokenCreator("CorrectBatteryHorseStaple");
    basicToken = tokenCreator.createToken(payload.encode());
    basicToken2 = tokenCreator.createToken(payload2.encode());
    System.setProperty("jwt.signing.key", "CorrectBatteryHorseStaple");
    
    httpClient = vertx.createHttpClient();
    RestAssured.port = port;
    DeploymentOptions mockOptions = new DeploymentOptions().setConfig(
      new JsonObject()
        .put("port", mockPort));
    logger.info("Deploying mock permissions module");
    vertx.deployVerticle(PermsMock.class.getName(), mockOptions, mockRes -> {
      if(mockRes.failed()) {
        mockRes.cause().printStackTrace();
        context.fail(mockRes.cause());
      } else {
        logger.info("Deploying Main Verticle (authtoken)");
        vertx.deployVerticle(MainVerticle.class.getName(), opt, mainRes -> {
          if(mainRes.failed()) {
            context.fail(mainRes.cause());
          } else {
            async.complete();
          }
        });
      }
    });
  }
  
  /*
  @Before
  public void setUp(TestContext context) {
   
  }

  @After
  public void tearDown(TestContext context) {
    
  }
  */
  
  @AfterClass
  public static void tearDownClass(TestContext context) {
    Async async = context.async();
    logger.info("Cleaning up after AuthTokenTest");
    vertx.close(x -> {
      async.complete();
    });
  }

  public AuthTokenTest() {
  }

  /**
   * Test simple permission handling. Since this test will run without Okapi or
   * mod_permissions, we need to be a little clever in the way we set up the
   * permissions we have. The whole test is based on the token authtoken creates
   * before login, that certifies that we have a tenant, but no logged-in user,
   * and no user-specific permissions. We can add permissions to this (empty)
   * set via the mechanisms of modulePermissions and ExtraPermissions.
   *
   * @param context
   */
  @Test 
  public void globTest(TestContext context) {
    async = context.async();
    String testGlob = "*bottle*cup";
    String testString1 = "WhitebottleBluecup";
    String testString2 = "WhitebotBluecu";
    context.assertTrue(Util.globMatch(testGlob, testString1));
    context.assertFalse(Util.globMatch(testGlob, testString2));
    async.complete();
  }
  
  
  @Test
  public void test1(TestContext context) {
    async = context.async();
    logger.debug("AuthToken test1 starting");

    RestAssuredClient c;
    Response r;

    // Simple request, mostly to see we can talk to the module
    // Not even a X-Okapi-Tenant header
    given()
      .get("/foo") // any path should work
      .then()
      .statusCode(400)
      .body(containsString("Missing header: X-Okapi-Tenant"));

    // A request without X-Okapi-Url header.
    // This succeeds (after fixing Folio-476).
    // Not quite sure if it should - without the ability to call back to
    // Okapi, we can not do much. Then again, Okapi always sets this header
    // before calling auth, so the whole thing is a bit theoretical. And the
    // module falls back to localhost:9130, which is not a bad guess...
    given()
      .header("X-Okapi-Tenant", tenant)
      .get("/foo")
      .then()
      .statusCode(202);

    // A request that should succeed
    // Even without any credentials in the request, we get back the whole lot,
    // most notbaly a token that certifies the fact that we have a tenant, but
    // have not yet identified ourself.
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Url", "http://localhost:9130")
      .get("/foo")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", startsWith("{\"_\":\""))
      .header("X-Okapi-Token", not(isEmptyString()))
      .header("Authorization", startsWith("Bearer "))
      .extract().response();
    final String noLoginToken = r.getHeader("X-Okapi-Token");

    // A request using the new nologin token with permissionRequired that will fail
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-Permissions-Required", "[\"foo.req\"]")
      .get("/foo")
      .then()
      .statusCode(403); // we don't have 'foo.req'

    // A request using the new nologin token with permissionDesired that will
    // succeed, but not give that perm
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-Permissions-Desired", "[\"foo.des\"]")
      .get("/foo")
      .then()
      .statusCode(202) // we don't have 'foo.req'
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", startsWith("{\"_\":\""))
      .header("X-Okapi-Token", not(isEmptyString()));

    // A request with the nologin token, with some modulePermissions to be
    // included in a new token
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-Module-Permissions",
        "{ \"bar\": [\"bar.first\",\"bar.second\"] }")
      .get("/foo")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", not(isEmptyString()))
      .extract().response();
    final String modTokens = r.getHeader("X-Okapi-Module-Tokens");
    JsonObject modtoks = new JsonObject(modTokens);
    String barToken = modtoks.getString("bar");

    // Make a request to bar, with the modulePermissions
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"bar.first\",\"bar.second\"]");

    // - A request with extraPermissions, needing one of them
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-Permissions-Desired", "extra.first")
      .header("X-Okapi-Permissions-Required", "extra.second")
      .header("X-Okapi-Extra-Permissions", "extra.first,extra.second")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.first\",\"extra.second\"]");

    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(202);

    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(403);
    
    //fail with a bad token
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", "THIS_IS_A_BAD_TOKEN")
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(401);
    
    //pass a desired permission through as a wildcard
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");

    async.complete();
    logger.debug("AuthToken test1 done");

  }
  
  public static int nextFreePort() {
    int maxTries = 10000;
    int port = ThreadLocalRandom.current().nextInt(49152, 65535);
    while (true) {
      if (isLocalPortFree(port)) {
        return port;
      } else {
        port = ThreadLocalRandom.current().nextInt(49152, 65535);
      }
      maxTries--;
      if (maxTries == 0) {
        return 8081;
      }
    }
  }

  private static boolean isLocalPortFree(int port) {
    try {
      new ServerSocket(port).close();
      return true;
    } catch (IOException e) {
      return false;
    }
  }
  
}
