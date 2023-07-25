package org.folio.auth.authtokenmodule;

import io.restassured.RestAssured;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;

import io.vertx.core.CompositeFuture;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.unit.TestContext;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.impl.ModulePermissionsSource;
import org.folio.auth.authtokenmodule.storage.ApiTokenStore;
import org.folio.auth.authtokenmodule.storage.RefreshTokenStore;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.ApiToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.LegacyAccessToken;
import org.folio.auth.authtokenmodule.tokens.ModuleToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;
import org.folio.okapi.common.XOkapiHeaders;
import org.junit.runner.RunWith;
import org.testcontainers.containers.PostgreSQLContainer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import static io.restassured.RestAssured.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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
  private static final String tenant = "roskilde";
  private static TokenCreator tokenCreator;
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String accessToken;
  private static String moduleToken;
  private static String dummyToken;
  private static String badAccessToken;
  private static String accessToken404;
  private static String inactiveToken;
  private static String refreshToken;
  private static String badRefreshToken;
  private static String tokenSystemPermission;
  private static JsonObject payloadDummySigningReq;
  private static JsonObject payloadSigningRequest;

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
    accessToken = new AccessToken(tenant, "jones", userUUID).encodeAsJWT(tokenCreator);
    var extraPerms1 = new JsonArray().add("auth.signtoken");
    moduleToken = new ModuleToken(tenant, "jones", userUUID, "", extraPerms1).encodeAsJWT(tokenCreator);
    var extraPerms2 = new JsonArray().add("auth.signtoken").add(PermsMock.SYS_PERM_SET).add("abc.def");
    tokenSystemPermission = new ModuleToken(tenant, "jones", userUUID, "", extraPerms2).encodeAsJWT(tokenCreator);
    dummyToken = new DummyToken(tenant, new JsonArray()).encodeAsJWT(tokenCreator);
    refreshToken = new RefreshToken(tenant, "jones", userUUID, "127.0.0.1").encodeAsJWE(tokenCreator);

    // Create some bad tokens, including one with a bad signing key.
    accessToken404 = new AccessToken(tenant, "jones", "404").encodeAsJWT(tokenCreator);
    inactiveToken = new AccessToken(tenant, "jones", "inactive").encodeAsJWT(tokenCreator);
    String badPassPhrase = "IncorrectBatteryHorseStaple";
    var badTokenCreator = new TokenCreator(badPassPhrase);
    badAccessToken = new AccessToken(tenant, "jones", userUUID).encodeAsJWT(badTokenCreator);
    badRefreshToken = new RefreshToken(tenant, "jones", userUUID, "127.0.0.1").encodeAsJWE(badTokenCreator);

    payloadDummySigningReq = new JsonObject()
        .put("dummy", true)
        .put("sub", "jones");

     payloadSigningRequest = new JsonObject()
        .put("user_id", userUUID)
        .put("sub", "joe");

    RestAssured.port = port;
    DeploymentOptions permsOptions = new DeploymentOptions()
        .setConfig(new JsonObject().put("port", mockPort));
    DeploymentOptions userOptions = new DeploymentOptions()
      .setConfig(new JsonObject().put("port", freePort));
    vertx.deployVerticle(PermsMock.class.getName(), permsOptions)
    .compose(x -> vertx.deployVerticle(UsersMock.class.getName(), userOptions))
    .compose(x -> vertx.deployVerticle(MainVerticle.class.getName(), opt))
    .onComplete(context.asyncAssertSuccess(y -> {
        var tenantAttributes = new JsonObject().put("module_to", "mod-authtoken-1.0.0");
        initializeTenantForTokenStore(tenant, tenantAttributes);
    }));
  }

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
  public void globTest() {
    String testGlob = "*bottle*cup";
    String testString1 = "WhitebottleBluecup";
    String testString2 = "WhitebotBluecu";

    assertThat(Util.globMatch(testGlob, testString1), is(true));
    assertThat(Util.globMatch(testGlob, testString2), is(false));
  }

  @Test
  public void jweTest(TestContext context) throws Exception {
    JsonObject ob = new JsonObject()
        .put("sub", "Ronald McDonald")
        .put("foo", "bar");
    // TODO Replace with new token type
    String jweToken = tokenCreator.createJWEToken(ob.encode());
    String reprocessedJson = tokenCreator.decodeJWEToken(jweToken);
    JsonObject reProcOb = new JsonObject(reprocessedJson);
    assertThat(reProcOb.getString("sub"), is("Ronald McDonald"));
  }

  @Test
  public void testNoUser() {
    PermsMock.handlePermsUsersEmpty = true;
    given()
        .header(MainVerticle.ZAP_CACHE_HEADER, "true")
        .header(XOkapiHeaders.TENANT, tenant)
        .header(XOkapiHeaders.TOKEN, accessToken)
        .header(XOkapiHeaders.URL, "http://localhost:" + mockPort)
        .get("/bar")
        .then()
        .statusCode(400)
        .body(containsString("User does not exist:"));
    PermsMock.handlePermsUsersEmpty = false;
  }

  @Test
  public void httpWithoutTenant() {
    // Simple request, mostly to see we can talk to the module
    // Not even a X-Okapi-Tenant header
    given()
        .get("/foo") // any path should work
        .then()
        .statusCode(400)
        .body(containsString("Missing header: X-Okapi-Tenant"));
  }

  @Test
  public void httpWithoutOkapiUrl() {
    // A request without X-Okapi-Url header; this fails with 400 error
    given()
        .header("X-Okapi-Tenant", tenant)
        .get("/foo")
        .then()
        .statusCode(400)
        .body(containsString("Missing header: X-Okapi-Url"));
  }

  @Test
  public void httpWithoutLoginToken() {
    // A request that should succeed even without any credentials in the request, we
    // get back the
    // whole lot, most notably a token that certifies the fact that we have a
    // tenant, but
    // have not yet identified ourself.
    Response r = given()
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
        .statusCode(403)
        .body(containsString("requires permission"))
        .body(containsString("foo.req"))
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
  }

  @Test
  public void testNoTokenAndPermissionRequired() {
    // A request without token but foo.req is required permission
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-Permissions-Required", "[\"foo.req\"]")
        .get("/foo")
        .then()
        .statusCode(403)
        .body(containsString("Token missing"))
        .body(containsString("foo.req"))
        .header("X-Okapi-Module-Tokens", not(emptyString()));
  }

  @Test
  public void testModuleTokens() {
    final String noLoginToken = given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .get("/foo")
        .then()
        .statusCode(202)
        .extract().header(XOkapiHeaders.TOKEN);

    final String modTokens = given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", noLoginToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-Module-Permissions",
            "{ \"bar\": [\"bar.first\",\"bar.second\"] }")
        .get("/foo")
        .then()
        .statusCode(202)
        .extract().header("X-Okapi-Module-Tokens");
    final JsonObject modtoks = new JsonObject(modTokens);
    final String barToken = modtoks.getString("bar");

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
        .statusCode(403)
        .body(containsString("Invalid token"));

    System.setProperty("allow.cross.tenant.requests", "");
    logger.info("The test cross-tenant request is denied when system property 'allow.cross.tenant.requests' is not set");
    given()
      .header("X-Okapi-Tenant", "test-tenant-1")
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(403);

    System.setProperty("allow.cross.tenant.requests", "false");
    logger.info("The test cross-tenant request is denied when system property 'allow.cross.tenant.requests' is 'false'");
    given()
      .header("X-Okapi-Tenant", "test-tenant-1")
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(403);

    System.setProperty("allow.cross.tenant.requests", "true");
    logger.info("The test cross-tenant request is permitted when system property 'allow.cross.tenant.requests' is 'true' and /user-tenants isn't empty");
    given()
      .header("X-Okapi-Tenant", "test-tenant-1")
      .header("X-Okapi-Token", barToken)
      .header("X-Okapi-Url", "http://localhost:" + freePort)
      .header("X-Okapi-Permissions-Desired", "bar.first")
      .header("X-Okapi-Permissions-Required", "bar.second")
      .get("/bar")
      .then()
      .statusCode(202);

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
  }

  @Test
  public void testAccessTokenAccepted() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", accessToken)
        .header("X-Okapi-Url", "http://localhost:" + mockPort)
        .header("X-Okapi-User-Id", userUUID)
        .get("/bar")
        .then()
        .statusCode(202);
  }

  @Test
  public void testAccessTokenForbidden() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", accessToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-User-Id", "1234567")
        .get("/bar")
        .then()
        .statusCode(403);
  }

  @Test
  public void testDummyTokenAccepted() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", dummyToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-User-Id", "1234567")
        .get("/bar")
        .then()
        .statusCode(202);
  }

  @Test
  public void testAccessTokenUserIdNotFound() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", accessToken404)
        .header("X-Okapi-Url", "http://localhost:" + mockPort)
        .header("X-Okapi-User-Id", "404")
        .get("/bar")
        .then()
        .statusCode(401)
        .assertThat().body(containsString("not exist"));
  }

  @Test
  public void testInactiveUserToken() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", inactiveToken)
        .header("X-Okapi-Url", "http://localhost:" + mockPort)
        .header("X-Okapi-User-Id", "inactive")
        .get("/bar")
        .then()
        .statusCode(401)
        .assertThat().body(containsString("not active"));
  }

  @Test
  public void testBadAccessToken() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", badAccessToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-User-Id", userUUID)
        .get("/bar")
        .then()
        .statusCode(401)
        .body(is("Invalid token"));
  }

  @Test
  public void testInvalidTokenFormat() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", "THIS_IS_A_BAD_TOKEN")
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-User-Id", "1234567")
        .get("/bar")
        .then()
        .statusCode(401)
        .body(is("Invalid token"));
  }

  @Test
  public void testAccessTokenExpiration() throws JOSEException, ParseException {
    var at = new AccessToken(tenant, "jones", userUUID);
    at.getClaims().put("exp", 0L);
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", at.encodeAsJWT(tokenCreator))
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(401).body(is("Invalid token"));
  }

  // NOTE: Any test with "_Legacy" in the method can be removed when we remove
  // the LegacyAccessToken token type after it is fully depreciated.

  @Test
  public void testEmptyTokenWithNoTenant_Legacy() {
    given()
        .header("X-Okapi-Token", accessToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("Content-type", "application/json")
        .post("/token")
        .then()
        .statusCode(400).body(containsString("Missing header: X-Okapi-Tenant"));
  }

  @Test
  public void testEmptyTokenWithNoUrl_Legacy() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", accessToken)
        .header("Content-type", "application/json")
        .post("/token")
        .then()
        .statusCode(400).body(containsString("Missing header: X-Okapi-Url"));
  }

  @Test
  public void testEmptyTokenSigningRequest_Legacy() {
    given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", accessToken)
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("Content-type", "application/json")
        .post("/token")
        .then()
        .statusCode(401).body(containsString("Missing required module-level permissions for endpoint"));
   }

    @Test
    public void testBadTokenSigningRequest_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .body(payloadDummySigningReq.encode())
          .post("/token")
          .then()
          .statusCode(401)
          .body(containsString("Missing required module-level permissions for endpoint '/token': auth.signtoken"));
    }

    @Test
    public void testSigningRequestWithGoodTokenNoPayload_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", moduleToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .post("/token")
          .then()
          .statusCode(202);
    }

    @Test
    public void testSigningRequestGoodDummyTokenGoodPayload_Legacy() throws TokenValidationException {
      String token = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body(new JsonObject().put("payload", payloadDummySigningReq).encode())
          .post("/token")
          .then()
          .statusCode(201).contentType("application/json").extract().path("token");
      var td = (DummyToken)Token.parse(token, tokenCreator);
      assertThat(td.getClaim("sub"), is(payloadDummySigningReq.getString("sub")));
   }

    @Test
    public void testSigningRequestGoodAccessTokenGoodPayload_Legacy() throws TokenValidationException {
      logger.info("POST signing request with good token, good payload");
      String token = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body(new JsonObject().put("payload", payloadSigningRequest).encode())
          .post("/token")
          .then()
          .statusCode(201).contentType("application/json").extract().path("token");
      var lat = (LegacyAccessToken)Token.parse(token, tokenCreator);
      assertThat(lat.getClaim("sub"), is(payloadSigningRequest.getString("sub")));
      assertNull(lat.getClaim("exp"));
    }

    @Test
    public void testSigningRequestUnsupportedMethod_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body(new JsonObject().put("payload", payloadDummySigningReq).encode())
          .put("/token")
          .then()
          .statusCode(405);
    }

    @Test
    public void testSigningRequestGoodTokenBadPayload_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body("{")
          .post("/token")
          .then()
          .statusCode(400);
    }

    @Test
    public void testSigningRequestGoodTokenBadPayload2_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body(new JsonObject().put("noload", payloadDummySigningReq).encode())
          .post("/token")
          .then()
          .statusCode(400);
    }

    @Test
    public void testSigningRequestGoodTokenBadPayload3_Legacy() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token") + "\"]")
          .body(new JsonObject().put("payload", new JsonObject().put("x", 1)).encode())
          .post("/token")
          .then()
          .statusCode(400);
    }

    // Methods above this point can be removed when legacy tokens are depreciated.

    @Test
    public void testEmptyTokenWithNoTenant() {
      given()
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .post("/token/sign")
          .then()
          .statusCode(400).body(containsString("Missing header: X-Okapi-Tenant"));
    }

    @Test
    public void testEmptyTokenWithNoUrl() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("Content-type", "application/json")
          .post("/token/sign")
          .then()
          .statusCode(400).body(containsString("Missing header: X-Okapi-Url"));
    }

    @Test
    public void testEmptyTokenSigningRequest() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .post("/token/sign")
          .then()
          .statusCode(401).body(containsString("Missing required module-level permissions for endpoint"));
     }

      @Test
      public void testBadTokenSigningRequest() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .body(payloadDummySigningReq.encode())
            .post("/token/sign")
            .then()
            .statusCode(401)
            .body(containsString("Missing required module-level permissions for endpoint '/token/sign': auth.signtoken"));
      }

      @Test
      public void testSigningRequestWithGoodTokenNoPayload() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", moduleToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .post("/token/sign")
            .then()
            .statusCode(202);
      }

      @Test
      public void testSigningRequestGoodDummyTokenGoodPayload() throws TokenValidationException {
        String token = given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("payload", payloadDummySigningReq).encode())
            .post("/token/sign")
            .then()
            .statusCode(201).contentType("application/json").extract().path("token");
        var td = (DummyToken)Token.parse(token, tokenCreator);
        assertThat(td.getClaim("sub"), is(payloadDummySigningReq.getString("sub")));
      }

      @Test
      public void testSigningRequestGoodAccessTokenGoodPayload()
        throws TokenValidationException, JOSEException, ParseException {
        logger.info("POST signing request with good token, good payload");
        var response = given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("payload", payloadSigningRequest).encode())
            .post("/token/sign")
            .then()
            .statusCode(201).contentType("application/json");
        var at =(AccessToken)Token.parse(response.extract().path("accessToken"), tokenCreator);
        assertThat(at.getClaim("sub"), is(payloadSigningRequest.getString("sub")));
        assertNotNull(at.getClaim("exp"));

        String encryptedRT = response.extract().path("refreshToken");
        var rt = (RefreshToken)Token.parse(encryptedRT, tokenCreator);
        assertThat(rt.getClaim("sub"), is(payloadSigningRequest.getString("sub")));
        assertNotNull(rt.getClaim("exp"));
        assertNotNull(rt.getClaim("address"));
        assertNotNull(rt.getClaim("user_id"));
      }

      @Test
      public void testRefreshTokenUnsupportedMethod_Legacy() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
            .body(new JsonObject().put("userId", userUUID).put("sub", "jones").encode())
            .put("/refreshtoken")
            .then()
            .statusCode(405);
      }

      @Test
      public void testRefreshTokenBadPayload_Legacy() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
            .body("{")
            .post("/refreshtoken")
            .then()
            .statusCode(400);
      }

      @Test
      public void testRefreshTokenBadPayload2_Legacy() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
            .body(new JsonObject().put("sub", "jones").encode())
            .post("/refreshtoken")
            .then()
            .statusCode(400);
      }

      @Test
      public void testRefreshToken_Legacy() throws JOSEException, ParseException {
        logger.info("POST signing request for a refresh token");
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/refreshtoken") + "\"]")
            .body(new JsonObject().put("userId", userUUID).put("sub", "jones").encode())
            .post("/refreshtoken")
            .then()
            .statusCode(201)
            .header("Content-Type", "application/json");
      }

      @Test
      public void testSigningRequestUnsupportedMethod() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("payload", payloadDummySigningReq).encode())
            .put("/token/sign")
            .then()
            .statusCode(405);
      }

      @Test
      public void testSigningRequestGoodTokenBadPayload() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body("{")
            .post("/token/sign")
            .then()
            .statusCode(400);
      }

      @Test
      public void testSigningRequestGoodTokenBadPayload2() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("noload", payloadDummySigningReq).encode())
            .post("/token/sign")
            .then()
            .statusCode(400);
      }

      @Test
      public void testSigningRequestGoodTokenBadPayload3() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("payload", new JsonObject().put("x", 1)).encode())
            .post("/token/sign")
            .then()
            .statusCode(400);
      }

      @Test
      public void testRefreshTokenBadPayload() {
        given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
            .body("{")
            .post("/token/refresh")
            .then()
            .statusCode(400);
      }

    @Test
    public void testRefreshTokenBadRefreshToken() {
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", badRefreshToken).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(containsString("Invalid token"));
    }

    @Test
    public void testRefreshToken() throws JOSEException, ParseException {
      logger.info("POST signing request for a refresh token");

      var response = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
          .body(new JsonObject().put("payload", payloadSigningRequest).encode())
          .post("/token/sign")
          .then()
          .statusCode(201).contentType("application/json");

      String rt = response.extract().path("refreshToken");
      String at = response.extract().path("accessToken");

      logger.info("PUT /refresh (bad method)");
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", rt).encode())
          .put("/token/refresh")
          .then()
          .statusCode(405);

      String tokenContent = tokenCreator.decodeJWEToken(rt);

      logger.info("POST refresh token with bad tenant");
      String payloadBadTenant = new JsonObject(tokenContent).put("tenant", "foo").encode();
      String refreshTokenBadTenant = tokenCreator.createJWEToken(payloadBadTenant);
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", refreshTokenBadTenant).encode())
          .post("/token/refresh")
          .then()
          .statusCode(403).body(containsString("Invalid token"));

      logger.info("POST refresh token with bad address");
      String refreshTokenBadAddress = tokenCreator.createJWEToken(
          new JsonObject(tokenContent).put("address", "foo").encode());
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", refreshTokenBadAddress).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(containsString("Invalid token"));

      logger.info("POST refresh token with bad expiry");
      String refreshTokenBadExpiry = tokenCreator.createJWEToken(
          new JsonObject(tokenContent).put("exp", 0L).encode());
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", refreshTokenBadExpiry).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(containsString("Invalid token"));

      logger.info("POST refresh token to get a new refresh and access token");
      final String refreshedAccessToken = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", rt).encode())
          .post("/token/refresh")
          .then()
          .statusCode(201)
          .extract().body().path("accessToken");

      logger.info(String.format("Test with 'refreshed' token: %s", refreshedAccessToken));
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", refreshedAccessToken)
          .header("X-Okapi-Url", "http://localhost:" + mockPort)
          .header("X-Okapi-User-Id", userUUID)
          .get("/bar")
          .then()
          .statusCode(202);
    }

    @Test
    public void testRefreshTokenSingleUse() throws JOSEException, ParseException {
      logger.info("POST signing request for a refresh token");
      var response = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
          .body(new JsonObject().put("payload", payloadSigningRequest).encode())
          .post("/token/sign")
          .then()
          .statusCode(201).contentType("application/json");

      String rt = response.extract().path("refreshToken");
      String at = response.extract().path("accessToken");

      logger.info("POST refresh token to get a new refresh and access token");
      final String refreshedAccessToken = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", at)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", rt).encode())
          .post("/token/refresh")
          .then()
          .statusCode(201)
          .extract().body().path("accessToken");

      logger.info("POST same refresh token a second time to simulate token attack/leakage");
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", refreshedAccessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", rt).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(is("Invalid token"));
    }

    @Test
    public void testAllTokensRevokedAfterOneTokenIsRevoked() throws JOSEException, ParseException {
      logger.info("Create three refresh tokens to simulate multiple logins");
      var tokens = new ArrayList<String>();
      for (int i = 0; i < 3; i++) {
        String refreshToken = given()
            .header("X-Okapi-Tenant", tenant)
            .header("X-Okapi-Token", accessToken)
            .header("X-Okapi-Url", "http://localhost:" + freePort)
            .header("Content-type", "application/json")
            .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/sign") + "\"]")
            .body(new JsonObject().put("payload", payloadSigningRequest).encode())
            .post("/token/sign")
            .then()
            .statusCode(201).contentType("application/json").extract().path("refreshToken");
            tokens.add(refreshToken);
      }

      logger.info("POST one of the refresh tokens to get a new refresh and access token");
      final String newAccessToken = given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", accessToken) // Using global AT for convenience here.
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", tokens.get(1)).encode())
          .post("/token/refresh")
          .then()
          .statusCode(201)
          .extract().body().path("accessToken");

      logger.info("POST same refresh token a second time to simulate token attack/leakage");
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", newAccessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", tokens.get(1)).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(is("Invalid token"));

      logger.info("Ensure that all tokens have now been revoked");
      for (int i = 0; i < 3; i++) {
        given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Token", newAccessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("Content-type", "application/json")
          .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/token/refresh") + "\"]")
          .body(new JsonObject().put("refreshToken", tokens.get(i)).encode())
          .post("/token/refresh")
          .then()
          .statusCode(401).body(is("Invalid token"));
      }
    }

    @Test
    public void testWildCardPermissions() throws JOSEException, ParseException {
      logger.info("Test with wildcard 400 /perms/users/id/permissions");
      PermsMock.handlePermsUsersPermissionsStatusCode = 400;
      given()
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Request-Id", "1234")
          .header("X-Okapi-Token", accessToken)
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
          .header("X-Okapi-Token", accessToken)
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
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + mockPort)
          .header("X-Okapi-Permissions-Desired", "extra.*bar")
          .get("/bar")
          .then()
          .statusCode(400);
      PermsMock.handlePermsUsersPermissionsStatusCode = 200;

      // Pass a desired permission through as a wildcard.
      logger.info("Test with wildcard permission");
      given()
          .header("Authtoken-Refresh-Cache", "true")
          .header("X-Okapi-Tenant", tenant)
          .header("X-Okapi-Request-Id", "1234")
          .header("X-Okapi-Token", accessToken)
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
          .header("X-Okapi-Token", accessToken)
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
          .header("X-Okapi-Token", moduleToken)
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
          .header("X-Okapi-Token", moduleToken)
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
          .header("X-Okapi-Token", moduleToken)
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
          .header("X-Okapi-Token", moduleToken)
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
          .header("X-Okapi-Token", moduleToken)
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
          .header("X-Okapi-Token", accessToken)
          .header("X-Okapi-Url", "http://localhost:" + freePort)
          .header("X-Okapi-Permissions-Desired", "extra.*bar")
          .get("/bar")
          .then()
          .statusCode(400);
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
  public void testAdminHealth() {
    given()
        .get("/admin/health")
        .then()
        .statusCode(200)
        .contentType("text/plain")
        .body(is("OK"));
  }

  private static String getMagicPermission(String endpoint) {
    return String.format("%s.execute", Base64.encode(endpoint));
  }

  @Test
  public void testStoreSaveRefreshToken(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    var rt = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    ts.saveToken(rt)
        .compose(x -> ts.checkTokenNotRevoked(rt))
        .onComplete(context.asyncAssertSuccess());
  }

  @Test
  public void testStoreRefreshTokenNotFound(TestContext context) {
    var ts = new RefreshTokenStore(vertx, tenant);
    // A RefreshToken which doesn't exist is treated as revoked.
    var unsavedToken = new RefreshToken(tenant, "jones", userUUID, "http://localhost:" + port);
    ts.checkTokenNotRevoked(unsavedToken).onComplete(context.asyncAssertFailure(e -> {
      assertThat(((TokenValidationException)e).getHttpResponseCode(), is(401));
      assertThat(e.getMessage(), containsString("not exist"));
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
      assertThat(((TokenValidationException)e).getHttpResponseCode(), is(401));
      assertThat(e.getMessage(), containsString("expired"));
      assertThat(e.getMessage(), containsString("revoked"));
    }));
  }

  @Test
  public void testStoreSaveApiToken(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);
    var apiToken = new ApiToken(tenant);
    ts.saveToken(apiToken).compose(x -> ts.checkTokenNotRevoked(apiToken))
        .onComplete(context.asyncAssertSuccess());
  }

  @Test
  public void testStoreApiTokenNotFound(TestContext context) {
    var ts = new ApiTokenStore(vertx, tenant, tokenCreator);
    // A ApiToken which doesn't exist in storage is treated as revoked.
    var unsavedToken = new ApiToken(tenant);
    ts.checkTokenNotRevoked(unsavedToken).onComplete(context.asyncAssertFailure(e -> {
      assertThat(((TokenValidationException)e).getHttpResponseCode(), is(401));
      assertThat(e.getMessage(), containsString("not found"));
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
          assertThat(((TokenValidationException)e).getHttpResponseCode(), is(401));
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
    var s1 = ts.saveToken(rt1);
    var s2 = ts.saveToken(rt2);
    var s3 = ts.saveToken(rt3);

    CompositeFuture.all(s1, s2, s3)
        .compose(a -> ts.checkTokenNotRevoked(rt2))
        .onComplete(context.asyncAssertSuccess()) // First check should succeed.
        .compose(a -> ts.checkTokenNotRevoked(rt2))
        .onComplete(context.asyncAssertFailure(b -> {
          assertLeakedOrRevoked(b);
        }))
        .compose(a -> ts.checkTokenNotRevoked(rt1))
        .onComplete(context.asyncAssertFailure(b -> {
          assertLeakedOrRevoked(b);
        }))
        .compose(a -> ts.checkTokenNotRevoked(rt3))
        .onComplete(context.asyncAssertFailure(b -> {
          assertLeakedOrRevoked(b);
        }));
  }

  private void assertLeakedOrRevoked(Throwable t) {
    assertThat(((TokenValidationException)t).getHttpResponseCode(), is(401));
    assertThat(t.getMessage(), containsString("leaked"));
    assertThat(t.getMessage(), containsString("revoked"));
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
    // Then save 5 tokens, two of which are expired. When each token is saved, the
    // method cleans up expired tokens, so after all 5 have been saved, only 3 should be
    // left.
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
  private static void initializeTenantForTokenStore(String tenant, JsonObject tenantAttributes) {
    // This request triggers postInit inside of AuthorizeApi.
    ExtractableResponse<Response> response = RestAssured.given()
        .header(XOkapiHeaders.TENANT, tenant)
        .header(XOkapiHeaders.URL, "http://localhost:" + port)
        .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/_/tenant") + "\"]")
        .header("X-Okapi-Url", "http://localhost:" + freePort)
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
        .header("X-Okapi-Url", "http://localhost:" + freePort)
        .header("X-Okapi-Permissions", "[\"" + getMagicPermission("/_/tenant") + "\"]")
        .get(location + "?wait=10000")
        .then()
        .statusCode(200)
        .body("complete", is(true));
  }
}
