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
import org.junit.runner.RunWith;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;


/**
 *
 * @author heikki
 */
@RunWith(VertxUnitRunner.class)
public class AuthTokenTest {
  private final Logger logger = LoggerFactory.getLogger("okapi");
  private static final String LS = System.lineSeparator();
  private static final String tenant = "Roskilde";
  private HttpClient httpClient;
  Vertx vertx;
  Async async;

  private final int port = Integer.parseInt(System.getProperty("port", "8081"));
  // TODO - Something wrong with passing the port around
  // The module defaults to 8081, so that's what we use here.

  @Before
  public void setUp(TestContext context) {
    logger.info("Setting up AuthTokenTest. Port=" + port);
    vertx = Vertx.vertx();
    JsonObject conf = new JsonObject()
      .put("port", port);
    DeploymentOptions opt = new DeploymentOptions()
      .setConfig(conf);
    vertx.deployVerticle(MainVerticle.class.getName(),
      opt, context.asyncAssertSuccess());
    httpClient = vertx.createHttpClient();
    RestAssured.port = port;
  }

  @After
  public void tearDown(TestContext context) {
    logger.info("Cleaning up after AuthTokenTest");
    async = context.async();
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

    async.complete();
    logger.debug("AuthToken test1 done");

  }


}
