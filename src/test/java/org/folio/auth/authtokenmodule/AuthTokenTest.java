package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.MainVerticle;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.Util;
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
import com.jayway.restassured.response.ValidatableResponse;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;
import guru.nidi.ramltester.restassured.RestAssuredClient;
import io.vertx.core.json.JsonArray;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.concurrent.ThreadLocalRandom;
import static org.folio.auth.authtokenmodule.MainVerticle.OKAPI_TOKEN_HEADER;
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
  private static TokenCreator badTokenCreator;
  private static JsonObject payload;
  private static JsonObject payloadBad;
  private static JsonObject payload2;
  private static JsonObject payload3;
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String basicToken;
  private static String basicToken2;
  private static String basicToken3;
  private static String basicBadToken;

  static int port;
  static int mockPort;
  static Vertx vertx;
  Async async;

  @BeforeClass
  public static void setUpClass(TestContext context) throws NoSuchAlgorithmException,
      JOSEException, ParseException {
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
    payloadBad = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("dummy", true)
      .put("sub", "jawnes");
    payload2 = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("sub", "jones");
    payload3 = new JsonObject()
      .put("user_id", userUUID)
      .put("tenant", tenant)
      .put("sub", "jones")
      .put("extra_permissions", new JsonArray().add("auth.signtoken"));
    //String passPhrase = "TheOriginalCorrectBatteryHorseStapleGun";
    String passPhrase = "CorrectBatteryHorseStaple";
    String badPassPhrase = "IncorrectBatteryHorseStaple";
    tokenCreator = new TokenCreator(passPhrase);
    badTokenCreator = new TokenCreator(badPassPhrase);
    basicToken = tokenCreator.createJWTToken(payload.encode());
    basicToken2 = tokenCreator.createJWTToken(payload2.encode());
    basicToken3 = tokenCreator.createJWTToken(payload3.encode());
    basicBadToken = badTokenCreator.createJWTToken(payloadBad.encode());

    System.setProperty("jwt.signing.key", passPhrase);

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
  public void jweTest(TestContext context) throws Exception {
    async = context.async();
    JsonObject ob = new JsonObject()
        .put("sub", "Ronald McDonald")
        .put("foo", "bar");
    String jweToken = tokenCreator.createJWEToken(ob.encode());
    String reprocessedJson = tokenCreator.decodeJWEToken(jweToken);
    JsonObject reProcOb = new JsonObject(reprocessedJson);
    context.assertTrue(reProcOb.getString("sub").equals("Ronald McDonald"));
    async.complete();
  }


  @Test
  public void test1(TestContext context) {
    async = context.async();
    logger.debug("AuthToken test1 starting");

    RestAssuredClient c;
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


    // A request without X-Okapi-Url header.
    // This succeeds (after fixing Folio-476).
    // Not quite sure if it should - without the ability to call back to
    // Okapi, we can not do much. Then again, Okapi always sets this header
    // before calling auth, so the whole thing is a bit theoretical. And the
    // module falls back to localhost:9130, which is not a bad guess...
    logger.info("Test request sans okapi-url header");
    given()
      .header("X-Okapi-Tenant", tenant)
      .get("/foo")
      .then()
      .statusCode(202);

    // A request that should succeed
    // Even without any credentials in the request, we get back the whole lot,
    // most notbaly a token that certifies the fact that we have a tenant, but
    // have not yet identified ourself.
    logger.info("Basic test, tenant and okapi url, no token");
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
    final String noLoginToken = r.getHeader(OKAPI_TOKEN_HEADER);

    // A request using the new nologin token with permissionRequired that will fail
    logger.info("Test with noLogin token and required perm");
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
    logger.info("Test with noLogin token and desired perm");
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
    logger.info("Test with noLogin token and module permissions");
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
    logger.info("Test with bar token and module permissions");
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
    logger.info("Test with bar token and extraPermissions");
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

    logger.info("Test with basicToken");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(202);

    logger.info("Test with basicBadToken");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicBadToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", userUUID)
      .get("/bar")
      .then()
      .statusCode(401);

    logger.info("Test with basicToken and a bad user id");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(403);

    //fail with a bad token
    logger.info("Test with bad token format");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", "THIS_IS_A_BAD_TOKEN")
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("X-Okapi-User-Id", "1234567")
      .get("/bar")
      .then()
      .statusCode(401);

    //pass a desired permission through as a wildcard
    logger.info("Test with wildcard permission");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:" + mockPort)
      .header("X-Okapi-Permissions-Desired", "extra.*bar")
      .get("/bar")
      .then()
      .statusCode(202)
      .header("X-Okapi-Permissions", "[\"extra.foobar\"]");

    //post a bad token signing request (no payload)
    logger.info("POST empty token signing request");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(401);

     //post a bad token signing request
    logger.info("POST bad token signing request");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("Content-type", "application/json")
      .body(payload.encode())
      .post("/token")
      .then()
      .statusCode(403);


    //get a good token signing request (no payload)
    logger.info("POST signing request with good token, no payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken3)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("Content-type", "application/json")
      .post("/token")
      .then()
      .statusCode(202);


    //get a good token signing request
    logger.info("POST signing request with good token, good payload");
    given()
      .header("X-Okapi-Tenant", tenant)
      .header("X-Okapi-Token", basicToken2)
      .header("X-Okapi-Url", "http://localhost:9130")
      .header("Content-type", "application/json")
      .header("X-Okapi-Permissions", "[\""+ getMagicPermission("/token") +"\"]")
      .body(new JsonObject().put("payload", payload).encode())
      .post("/token")
      .then()
      .statusCode(201);

    //get a refresh token
    logger.info("POST signing request for a refresh token");
    r = given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", basicToken2)
        .header("X-Okapi-Url", "http://localhost:9130")
        .header("Content-type", "application/json")
        .header("X-Okapi-Permissions", "[\""+ getMagicPermission("/refreshtoken") +"\"]")
        .body(new JsonObject().put("userId", userUUID).put("sub", "jones").encode())
        .post("/refreshtoken")
        .then()
        .statusCode(201)
        .header("Content-Type", "application/json")
        .extract().response();

    JsonObject refreshTokenResponse = new JsonObject(r.getBody().asString());
    final String refreshToken = refreshTokenResponse.getString("refreshToken");

    logger.info("POST refresh token to get a new access token");
    r = given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", basicToken2)
        .header("X-Okapi-Url", "http://localhost:9130")
        .header("Content-type", "application/json")
        .header("X-Okapi-Permissions", "[\""+ getMagicPermission("/refresh") +"\"]")
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
      //.header("X-Okapi-Token", basicToken)
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
        .header("X-Okapi-Permissions", "[\""+ getMagicPermission("/encrypted-token/create") +"\"]")
        .body(new JsonObject().put("passPhrase", secret).put("payload", tokenPayload).encode())
        .post("/encrypted-token/create")
        .then()
        .statusCode(201)
        .extract().response();

    String encryptedTokenResponse = r.getBody().asString();
    JsonObject encryptedTokenJson = new JsonObject(encryptedTokenResponse);
    String encryptedToken = encryptedTokenJson.getString("token");

    logger.info(String.format("Attempting to decrypt token %s", encryptedToken));
    r = given()
        .header("X-Okapi-Tenant", tenant)
        .header("X-Okapi-Token", basicToken)
        .header("X-Okapi-Permissions", "[\""+ getMagicPermission("/encrypted-token/decode") +"\"]")
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

  private String getMagicPermission(String endpoint) {
    return String.format("%s.execute", Base64.encode(endpoint));
  }

}