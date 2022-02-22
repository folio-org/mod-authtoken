package org.folio.auth.authtokenmodule;

import io.restassured.RestAssured;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;

import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.unit.TestContext;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.ModuleToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.okapi.common.OkapiToken;
import org.folio.okapi.common.XOkapiHeaders;
import org.junit.runner.RunWith;
import org.testcontainers.containers.PostgreSQLContainer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import static io.restassured.RestAssured.*;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyString;

import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.CoreMatchers.containsString;

@RunWith(VertxUnitRunner.class)
public class AuthTokenTest {

  private static final Logger logger = LogManager.getLogger("AuthTokenTest");
  private static final String LS = System.lineSeparator();
  private static final String tenant = "roskilde";
  private static HttpClient httpClient;
  private static TokenCreator tokenCreator;
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String basicToken;
  private static String basicToken2;
  private static String basicToken3;
  private static String basicBadToken;
  private static String token404;
  private static String tokenInactive;
  private static String tokenSystemPermission;

  static int port;
  static int mockPort;
  static int freePort;
  static Vertx vertx;
  Async async;

  @ClassRule
  public static PostgreSQLContainer<?> postgresSQLContainer = TokenStoreTestContainer.create();

  @BeforeClass
  public static void setUpClass(TestContext context) throws NoSuchAlgorithmException,
    JOSEException, ParseException {
    Async async = context.async();
    port = NetworkUtils.nextFreePort();
    mockPort = NetworkUtils.nextFreePort();
    freePort = NetworkUtils.nextFreePort();
    vertx = Vertx.vertx();

    logger.info("Setting up AuthTokenTest. Port=" + port);
    JsonObject conf = new JsonObject()
      .put("port", Integer.toString(port));
    DeploymentOptions opt = new DeploymentOptions()
      .setConfig(conf);

    // Create some good tokens.
    String passPhrase = "CorrectBatteryHorseStaple";
    System.setProperty("jwt.signing.key", passPhrase);
    tokenCreator = new TokenCreator(passPhrase);
    basicToken = new AccessToken(tenant, "jones", userUUID).encodeAsJWT(tokenCreator);
    basicToken2 = new AccessToken(tenant, "jones", userUUID).encodeAsJWT(tokenCreator);
    var extraPerms1 = new JsonArray().add("auth.signtoken");
    basicToken3 = new ModuleToken(tenant, "jones", userUUID, "", extraPerms1).encodeAsJWT(tokenCreator);
    var extraPerms2 = new JsonArray().add("auth.signtoken").add(PermsMock.SYS_PERM_SET).add("abc.def");
    tokenSystemPermission = new ModuleToken(tenant, "jones", userUUID, "", extraPerms2).encodeAsJWT(tokenCreator);

    // Create some bad tokens, including one with a bad signing key.
    token404 = new AccessToken(tenant, "jones", "404").encodeAsJWT(tokenCreator);
    tokenInactive = new AccessToken(tenant, "jones", "inactive").encodeAsJWT(tokenCreator);
    String badPassPhrase = "IncorrectBatteryHorseStaple";
    var badTokenCreator = new TokenCreator(badPassPhrase);
    basicBadToken = new AccessToken(tenant, "jones", userUUID).encodeAsJWT(badTokenCreator);

    RestAssured.port = port;
    DeploymentOptions mockOptions = new DeploymentOptions().setConfig(
      new JsonObject()
        .put("port", mockPort));
    logger.info("Deploying mock permissions module");
    vertx.deployVerticle(PermsMock.class.getName(), mockOptions, mockRes -> {
      if (mockRes.failed()) {
        mockRes.cause().printStackTrace();
        context.fail(mockRes.cause());
      } else {
        logger.info("Deploying Main Verticle (authtoken)");
        vertx.deployVerticle(MainVerticle.class.getName(), opt, mainRes -> {
          if (mainRes.failed()) {
            context.fail(mainRes.cause());
          } else {
            async.complete();
          }
        });
      }
    });

    initializeTenantForTokenStore(tenant, new JsonObject());
  }

  @AfterClass
  public static void tearDownClass(TestContext context) {
    Async async = context.async();
    logger.info("Cleaning up after AuthTokenTest");
    vertx.close(x -> {
      async.complete();
    });
  }

  public AuthTokenTest() {}

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
  public void jweTest(TestContext context) throws Exception {
    async = context.async();
    JsonObject ob = new JsonObject()
      .put("sub", "Ronald McDonald")
      .put("foo", "bar");
    // TODO Replace with new token type
    String jweToken = tokenCreator.createJWEToken(ob.encode());
    String reprocessedJson = tokenCreator.decodeJWEToken(jweToken);
    JsonObject reProcOb = new JsonObject(reprocessedJson);
    context.assertTrue(reProcOb.getString("sub").equals("Ronald McDonald"));
    async.complete();
  }

  @Test
  public void testNoUser(TestContext context) {
    PermsMock.handlePermsUsersEmpty = true;
    given()
      .header(MainVerticle.ZAP_CACHE_HEADER, "true")
      .header(XOkapiHeaders.TENANT, tenant)
      .header(XOkapiHeaders.TOKEN, basicToken2)
      .header(XOkapiHeaders.URL, "http://localhost:" + mockPort)
      .get("/bar")
      .then()
      .statusCode(400)
      .body(containsString("User does not exist:"));
    PermsMock.handlePermsUsersEmpty = false;
  }

  @Test
  public void testHttpEndpoints(TestContext context) throws JOSEException, ParseException {
    async = context.async();
    logger.debug("AuthToken test1 starting");

    JsonObject payloadDummy = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("dummy", true)
      .put("sub", "jones");

    JsonObject payloadAccess = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("sub", "joe");

    Response r;

    logger.info("Beginning tests");

    logger.info("Test simple request, sans tenant and token");
    // Simple request, mostly to see we can talk to the module
    // Not even a X-Okapi-Tenant header
    given()
      .get("/foo") // any path should work
      .then()
      .statusCode(400)
      .body(containsString("Missing header: X-Okapi-Tenant"));

    // A request without X-Okapi-Url header; this fails with 400 error
    logger.info("Test request sans okapi-url header");
    given()
      .header("X-Okapi-Tenant", tenant)
      .get("/foo")
      .then()
      .statusCode(400)
      .body(containsString("Missing header: X-Okapi-Url"));

    // A request that should succeed
    // Even without any credentials in the request, we get back the whole lot,
    // most notbaly a token that certifies the fact that we have a tenant, but
    // have not yet identified ourself.
    logger.info("Basic test, tenant and okapi url, no token");
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .get("/foo")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", startsWith("{\"_\":\""))
      .header("X-Okapi-Token", not(emptyString()))
      .header("Authorization", startsWith("Bearer "))
      .extract().response();
    final String noLoginToken = r.getHeader(XOkapiHeaders.TOKEN);

    // A request using the new nologin token with permissionRequired that will fail
    logger.info("Test with noLogin token and required perm");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Required", "[\"foo.req\"]")
      .get("/foo")
      .then()
      .statusCode(403) // we don't have 'foo.req'
      .header("X-Okapi-Module-Tokens", not(emptyString()));

    // A request using the new nologin token with permissionDesired that will
    // succeed, but not give that perm
    logger.info("Test with noLogin token and desired perm");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "[\"foo.des\"]")
      .get("/foo")
      .then()
      .statusCode(202) // we don't have 'foo.req'
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", startsWith("{\"_\":\""))
      .header("X-Okapi-Token", not(emptyString()));

    // A request with the nologin token, with some modulePermissions to be
    // included in a new token
    logger.info("Test with noLogin token and module permissions");
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", noLoginToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Module-Permissions",
        "{ \"bar\": [\"bar.first\",\"bar.second\"] }")
      .get("/foo")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[]")
      .header("X-Okapi-Module-Tokens", not(emptyString()))
      .extract().response();
    final String modTokens = r.getHeader("X-Okapi-Module-Tokens");
    JsonObject modtoks = new JsonObject(modTokens);
    String barToken = modtoks.getString("bar");

    logger.info("Test with conflicting Authorization and X-Okapi-Token");
    given()
      .header("Authorization", "guf")
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(400)
      .body(containsString("Conflicting token information in Authorization and "));

    logger.info("Test with conflicting Authorization and X-Okapi-Token (2)");
    given()
      .header("Authorization", "Bearer guf")
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(400)
      .body(containsString("Conflicting token information in Authorization and "));

    logger.info("Test with Authorization=X-Okapi-Token");
    given()
      .header("Authorization", "Bearer " + barToken)
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Test with Authorization and no X-Okapi-Token");
    given()
      .header("Authorization", "Bearer " + barToken)
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Test with conflicting token and tenant not in sync");
    given()
      .header("X-Okapi-Tenant", "guf")
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(403);
      // TODO Should we be expecting certain error messages? This seems brittle.
      //.body(containsString("Invalid token for access"));

    // Make a request to bar, with the modulePermissions
    logger.info("Test with bar token and module permissions");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"bar.first\",\"bar.second\"]");

    // - A request with extraPermissions, needing one of them
    logger.info("Test with bar token and extraPermissions");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "extra.first")
      .header("X-Okapi-Permissions-Required", "extra.second")
      .header("X-Okapi-Extra-Permissions", "extra.first,extra.second")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.first\",\"extra.second\"]");

    logger.info("Test with basicToken");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(202);

      logger.info("Test with basicToken and a bad user id");
      given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", basicToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-User-Id", "1234567")
        .get("/bar")
        .then()
        .statusCode(403);

    logger.info("Test with dummyToken and a bad user id");
    String dummyToken = new DummyToken(tenant, new JsonArray()).encodeAsJWT(tokenCreator);
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", dummyToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Test with 404 user token");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", token404)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-User-Id", "404")
      .get("/bar")
      .then()
      .statusCode(401)
      .assertThat().body(containsString("not exist"));

    logger.info("Test with inactive user token");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", tokenInactive)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-User-Id", "inactive")
      .get("/bar")
      .then()
      .statusCode(401)
      .assertThat().body(containsString("not active"));

    logger.info("Test with basicBadToken");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicBadToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(401);


    //fail with a bad token
    logger.info("Test with bad token format");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", "THIS_IS_A_BAD_TOKEN")
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(401);

    logger.info("Test with wildcard permission - bad X-Okapi-Url");
    given()
      .header("Authtoken-Refresh-Cache", "true")
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400).body(containsString("Connection refused"))
      .header("X-Okapi-Module-Tokens", not(emptyString()));
    // used to be 401.. But connection refused is hardly forbidden..

    logger.info("Test with wildcard 400 /perms/users/id/permissions");
    PermsMock.handlePermsUsersPermissionsStatusCode = 400;
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);
    PermsMock.handlePermsUsersPermissionsStatusCode = 200;

    logger.info("Test with wildcard / bad /perms/users/id/permissions");
    PermsMock.handlePermsUsersPermissionsFail = true;
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);
    PermsMock.handlePermsUsersPermissionsFail = false;

    logger.info("Test with wildcard 404 /perms/users/id/permissions");
    PermsMock.handlePermsUsersPermissionsStatusCode = 404;
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);
    PermsMock.handlePermsUsersPermissionsStatusCode = 200;

    //pass a desired permission through as a wildcard
    logger.info("Test with wildcard permission");
    given()
      .header("Authtoken-Refresh-Cache", "true")
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");

    logger.info("Test with wildcard permission - from cache");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Test with extra /perms/permissions status failure");
    PermsMock.handlePermsPermissionsStatusCode = 400;
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);
    PermsMock.handlePermsPermissionsStatusCode = 200;

    logger.info("Test with extra /perms/permissions response error");
    PermsMock.handlePermsPermissionsFail = true;
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);
    PermsMock.handlePermsPermissionsFail = false;

    logger.info("Test with extra permissions");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");

    logger.info("Test with extra permissions cached");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");

    logger.info("Test with extra permissions - timeout = 0");
    ModulePermissionsSource.setCacheTimeout(0);
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");
    ModulePermissionsSource.setCacheTimeout(60);

    logger.info("Test with wildcard permission - zap cache");
    given()
      .header("Authtoken-Refresh-Cache", "true")
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(400);

    logger.info("POST empty token with no Tenant");
    given()
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(400).body(containsString("Missing header: X-Okapi-Tenant"));

    logger.info("POST empty token with no X-Okapi-URl");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(400).body(containsString("Missing header: X-Okapi-Url"));

    //post a bad token signing request (no payload)
    logger.info("POST empty token signing request");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(401).body(containsString("Missing required module-level permissions for endpoint"));

    //post a bad token signing request
    logger.info("POST bad token signing request");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .body(payloadDummy.encode())
      .post("/token")
      .then()
      .statusCode(403).body(containsString("Missing permissions to access endpoint '/token'"));

    logger.info("POST signing request with good token, no payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(202);

    //get a good dummy token signing request
    logger.info("POST signing request with good token, good payload");
    String token = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body(new JsonObject().put("payload", payloadDummy).encode())
      .post("/token")
      .then()
      .statusCode(201).contentType("application/json").extract().path("token");
    context.assertEquals(payloadDummy.getString("sub"), new OkapiToken(token).getUsernameWithoutValidation());

    //get a good access token signing request
    logger.info("POST signing request with good token, good payload");
    token = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body(new JsonObject().put("payload", payloadAccess).encode())
      .post("/token")
      .then()
      .statusCode(201).contentType("application/json").extract().path("token");
    context.assertEquals(payloadAccess.getString("sub"), new OkapiToken(token).getUsernameWithoutValidation());

    logger.info("PUT signing request with good token, good payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body(new JsonObject().put("payload", payloadDummy).encode())
      .put("/token")
      .then()
      .statusCode(400).body(containsString("Unsupported operation: PUT"));

    logger.info("POST signing request with good token, bad payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body("{")
      .post("/token")
      .then()
      .statusCode(400).body(containsString("Unable to decode "));

    logger.info("POST signing request with good token, bad payload 2");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body(new JsonObject().put("noload", payloadDummy).encode())
      .post("/token")
      .then()
      .statusCode(400).body(containsString("Valid 'payload' field is required"));

    logger.info("POST signing request with good token, bad payload 3");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
      .body(new JsonObject().put("payload", new JsonObject().put("x", 1)).encode())
      .post("/token")
      .then()
      .statusCode(400).body(containsString("Payload must contain a 'sub' field"));

    //get a refresh token (bad method)
    logger.info("PUT signing request for a refresh token");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
      .body(new JsonObject().put("userId", userUUID).put("sub", "jones").encode())
      .put("/refreshtoken")
      .then()
      .statusCode(400).body(containsString("Invalid method"));

    //get a refresh token (bad payload)
    logger.info("GET signing request for a refresh token (bad payload)");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
      .body("{")
      .post("/refreshtoken")
      .then()
      .statusCode(400).body(containsString("Unable to parse content: "));

    //get a refresh token (bad payload 2)
    logger.info("GET signing request for a refresh token (bad payload)");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
      .body(new JsonObject().put("sub", "jones").encode())
      .post("/refreshtoken")
      .then()
      .statusCode(400).body(containsString("Unable to parse content: "));

    //get a refresh token
    logger.info("POST signing request for a refresh token");
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
      .body(new JsonObject().put("userId", userUUID).put("sub", "jones").encode())
      .post("/refreshtoken")
      .then()
      .statusCode(201)
      .header("Content-Type", "application/json")
      .extract().response();

    JsonObject refreshTokenResponse = new JsonObject(r.getBody().asString());
    final String refreshToken = refreshTokenResponse.getString("refreshToken");
    logger.info("refreshToken=" + refreshToken);

    logger.info("PUT /refresh (bad method)");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", refreshToken).encode())
      .put("/refresh")
      .then()
      .statusCode(400).body(containsString("Invalid method for this endpoint"));

    logger.info("POST /refresh with bad payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body("{")
      .post("/refresh")
      .then()
      .statusCode(400).body(containsString("Unable to parse content of refresh token request: "));

    logger.info("POST /refresh with bad refreshToken");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", basicBadToken).encode())
      .post("/refresh")
      .then()
      .statusCode(401).body(containsString("Invalid token"));

    String tokenContent = tokenCreator.decodeJWEToken(refreshToken);

    logger.info("POST refresh token with bad tenant");
    String payloadBadTenant = new JsonObject(tokenContent).put("tenant", "foo").encode();
    String refreshTokenBadTenant = tokenCreator.createJWEToken(payloadBadTenant);
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", refreshTokenBadTenant).encode())
      .post("/refresh")
      .then()
      .statusCode(403).body(containsString("Invalid token"));

    logger.info("POST refresh token with bad address");

    String refreshTokenBadAddress = tokenCreator.createJWEToken(
      new JsonObject(tokenContent).put("address", "foo").encode());
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", refreshTokenBadAddress).encode())
      .post("/refresh")
      .then()
      .statusCode(401).body(containsString("Invalid token"));

    logger.info("POST refresh token with bad expiry");
    String refreshTokenBadExpiry = tokenCreator.createJWEToken(
      new JsonObject(tokenContent).put("exp", 0L).encode());
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", refreshTokenBadExpiry).encode())
      .post("/refresh")
      .then()
      .statusCode(401).body(containsString("Invalid token"));

    logger.info("POST refresh token to get a new access token");
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refresh") + "\"]")
      .body(new JsonObject().put("refreshToken", refreshToken).encode())
      .post("/refresh")
      .then()
      .statusCode(201)
      .extract().response();

    JsonObject refreshResponse = new JsonObject(r.getBody().asString());
    final String accessToken = refreshResponse.getString("token");

    logger.info(String.format("Test with 'refreshed' token: %s", accessToken));
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", accessToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Get an encrypted token as a service");
    String secretWord = "kamehameha";
    JsonObject tokenPayload = new JsonObject()
      .put("type", "resetToken")
      .put("secret", secretWord);
    String secret = "THEYRECOMINGTOTAKEMEAWAYHAHATHEYRECOMINGTOTAKEMEAWAY";
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/create") + "\"]")
      .body(new JsonObject().put("passPhrase", secret).put("payload", tokenPayload).encode())
      .post("/encrypted-token/create")
      .then()
      .statusCode(201)
      .extract().response();

    logger.info("Bad method for encrypted token as a service");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/create") + "\"]")
      .body(new JsonObject().put("passPhrase", secret).put("payload", tokenPayload).encode())
      .put("/encrypted-token/create")
      .then()
      .statusCode(400).body(containsString("Invalid method for this endpoint"));

    logger.info("Bad body for encrypted token as a service");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/create") + "\"]")
      .body("{") // invalid JSON
      .post("/encrypted-token/create")
      .then()
      .statusCode(400).body(containsString("Unable to parse content: "));

    logger.info("Bad payload for encrypted token as a service");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/create") + "\"]")
      .body(new JsonObject().put("passPhrase", secret).put("payload", "gyf").encode())
      .post("/encrypted-token/create")
      .then()
      .statusCode(400).body(containsString("java.lang.String cannot be cast to class io.vertx.core.json.JsonObject"));

    String encryptedTokenResponse = r.getBody().asString();
    JsonObject encryptedTokenJson = new JsonObject(encryptedTokenResponse);
    String encryptedToken = encryptedTokenJson.getString("token");

    logger.info("/encrypted-token/decode with bad method");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/decode") + "\"]")
      .body(new JsonObject().put("passPhrase", secret).put("token", encryptedToken).encode())
      .put("/encrypted-token/decode")
      .then()
      .statusCode(400).body(containsString("Invalid method for this endpoint"));

    logger.info("/encrypted-token/decode with bad payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/decode") + "\"]")
      .body("{")
      .post("/encrypted-token/decode")
      .then()
      .statusCode(400).body(containsString("Unable to parse content: "));

    logger.info("/encrypted-token/decode with bad payload (null value for passPhrase)");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/decode") + "\"]")
      .body(new JsonObject().putNull("passPhrase").put("token", encryptedToken).encode())
      .post("/encrypted-token/decode")
      .then()
      .statusCode(400).body(containsString("Unable to parse content: "));

    logger.info(String.format("/encrypted-token/decode token %s", encryptedToken));
    r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/encrypted-token/decode") + "\"]")
      .body(new JsonObject().put("passPhrase", secret).put("token", encryptedToken).encode())
      .post("/encrypted-token/decode")
      .then()
      .statusCode(201)
      .extract().response();

    JsonObject decodedJson = new JsonObject(r.body().asString());
    context.assertTrue(decodedJson.getJsonObject("payload").getString("secret").equals(secretWord));

    async.complete();
    logger.debug("AuthToken test1 done");
  }

  @Test
  public void testExpandSystemPermission() {
    Response r = given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Request-Id", "1234")
      .header("X-Okapi-Token", tokenSystemPermission)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Required",
        PermsMock.SYS_PERM_SUB_01 + "," + PermsMock.SYS_PERM_SUB_02)
      .get("/testsysperm")
      .then()
      .statusCode(202)
      .extract().response();

    String headers = r.getHeader("X-Okapi-Permissions");
    assertTrue(headers.contains(PermsMock.SYS_PERM_SUB_01));
    assertTrue(headers.contains(PermsMock.SYS_PERM_SUB_02));
  }

  @Test
  public void testAdminHealth()  {
    given()
      .get("/admin/health")
      .then()
      .statusCode(200)
      .contentType("text/plain")
      .body(is("OK"));
  }

  private String getMagicPermission(String endpoint) {
    return String.format("%s.execute", Base64.encode(endpoint));
  }

  @Test
  public void testStoreSaveRefreshToken(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    var rt = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    ts.saveToken(rt, false)
      .compose(x -> ts.checkTokenNotRevoked(rt))
      .onComplete(context.asyncAssertSuccess());
  }

  @Test
  public void testStoreRefreshTokenNotFound(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    // A RefreshToken which doesn't exist is treated as revoked.
    var unsavedToken = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    ts.checkTokenNotRevoked(unsavedToken).onComplete(context.asyncAssertFailure(e -> {
      assertThat(e.getMessage(), containsString("revoked"));
    }));
  }

  @Test
  public void testStoreRefreshTokenExpired(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    var expiredToken = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var now = Instant.now().getEpochSecond();
    expiredToken.setExpiresAt(now - 10);
    ts.checkTokenNotRevoked(expiredToken).onComplete(context.asyncAssertFailure(e -> {
      assertThat(e.getMessage(), containsString("expired"));
      assertThat(e.getMessage(), containsString("revoked"));
    }));
  }

  @Test
  public void testStoreSaveApiToken(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);
    var apiToken = new ApiToken(tenant);
    ts.saveToken(apiToken).compose(x ->  ts.checkTokenNotRevoked(apiToken))
      .onComplete(context.asyncAssertSuccess());
  }

  @Test
  public void testStoreApiTokenNotFound(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);
    // A ApiToken which doesn't exist in storage is treated as revoked.
    var unsavedToken = new ApiToken(tenant);
    ts.checkTokenNotRevoked(unsavedToken).onComplete(context.asyncAssertFailure(e -> {
      assertThat(e.getMessage(), containsString("revoked"));
    }));
  }

  @Test
  public void testApiTokenRevoked(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);
    var apiToken = new ApiToken(tenant);
    ts.saveToken(apiToken)
      .compose(x -> ts.checkTokenNotRevoked(apiToken))
      .compose(x -> ts.revokeToken(apiToken))
      .onComplete(context.asyncAssertSuccess())
      .compose(x -> ts.checkTokenNotRevoked(apiToken))
      .onComplete(context.asyncAssertFailure(e -> {
        assertThat(e.getMessage(), containsString("revoked"));
      }));
  }

  @Test
  public void testStoreRefreshTokenSingleUse(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    // Create and save some tokens.
    var rt1 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt2 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt3 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var s1 = ts.saveToken(rt1, false);
    var s2 = ts.saveToken(rt2, false);
    var s3 = ts.saveToken(rt3, false);

    CompositeFuture.all(s1, s2, s3)
      .compose(a -> ts.checkTokenNotRevoked(rt2))
      .onComplete(context.asyncAssertSuccess()) // First check should succeed.
      .compose(a -> ts.checkTokenNotRevoked(rt2))
      .onComplete(context.asyncAssertFailure(b ->
        assertThat(b.getMessage(), containsString("revoked"))
      ))
      .compose(a -> ts.checkTokenNotRevoked(rt1))
      .onComplete(context.asyncAssertFailure(b ->
        assertThat(b.getMessage(), containsString("revoked"))
      ))
      .compose(a -> ts.checkTokenNotRevoked(rt3))
      .onComplete(context.asyncAssertFailure(b ->
         assertThat(b.getMessage(), containsString("revoked"))
      ));
  }

  @Test
  public void testStoreCleanupExpired(TestContext context) {
    // Create some tokens.
    var rt1 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt2 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt3 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt4 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    var rt5 = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);

    // Set a few tokens' expires at time to simulate expiration.
    var now = Instant.now().getEpochSecond();
    rt2.setExpiresAt(now - 10); // Would have expired 10 seconds ago.
    rt4.setExpiresAt(now - 20); // Would have expired 20 seconds ago.

    var ts = new RefreshTokenStore(vertx, tenant);

    // Other tests could have added tokens to storage, so remove all of those first.
    // Then save 5 tokens, two of which are expired. When each token is saved, the method
    // cleans up expired tokens, so after all 5 have been saved, only 3 should be left.
    ts.removeAll()
      .compose(x -> {
        var s1 = ts.saveToken(rt1, true);
        var s2 = ts.saveToken(rt2, true);
        var s3 = ts.saveToken(rt3, true);
        var s4 = ts.saveToken(rt4, true);
        var s5 = ts.saveToken(rt5, true);
        return CompositeFuture.all(s1, s2, s3, s4, s5);
      })
      .compose(y -> ts.countTokensStored(tenant))
      .onComplete(context.asyncAssertSuccess(count -> assertThat(count, is(3))));
  }

  @Test
  public void testStoreGetApiTokensForTenant(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);

    ts.removeAll()
      .compose(x -> {
        var s1 = ts.saveToken(new ApiToken(tenant));
        var s2 = ts.saveToken(new ApiToken(tenant));
        var s3 = ts.saveToken(new ApiToken(tenant));
        var s4 = ts.saveToken(new ApiToken(tenant));
        var s5 = ts.saveToken(new ApiToken(tenant));
        return CompositeFuture.all(s1, s2, s3, s4, s5);
      })
      .compose(x -> ts.getApiTokensForTenant(tenant))
      .onComplete(context.asyncAssertSuccess(x -> assertThat(x.size(), is(5))));
  }

  // Taken from folio-vertx-lib's tests. Causes postInit to be called.
  static void initializeTenantForTokenStore(String tenant, JsonObject tenantAttributes) {
    // This request triggers postInit inside of AuthorizeApi.
    ExtractableResponse<Response> response = RestAssured.given()
        .header(XOkapiHeaders.TENANT, tenant)
        .header(XOkapiHeaders.URL, "http://localhost:" + port)
        .header("Content-Type", "application/json")
        .body(tenantAttributes.encode())
        .post("/_/tenant")
        .then()
        .extract();

    if (response.statusCode() == 204) {
      return;
    }

    assertThat(response.statusCode(), is(201));
    String location = response.header("Location");
    JsonObject tenantJob = new JsonObject(response.asString());
    assertThat(location, is("/_/tenant/" + tenantJob.getString("id")));

    RestAssured.given()
        .header(XOkapiHeaders.TENANT, tenant)
        .get(location + "?wait=10000")
        .then().statusCode(200)
        .body("complete", is(true));
  }
}
