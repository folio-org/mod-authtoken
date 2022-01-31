package org.folio.auth.authtokenmodule;

import io.vertx.core.DeploymentOptions;
import io.vertx.sqlclient.PreparedQuery;
import io.vertx.pgclient.PgPool;

import io.vertx.core.Future;
// import io.restassured.RestAssured;
// import io.restassured.builder.RequestSpecBuilder;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.testcontainers.containers.PostgreSQLContainer;

import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;

import java.io.IOException;
import java.util.function.Function;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import org.folio.okapi.common.XOkapiHeaders;
import org.folio.tlib.postgres.TenantPgPool;

@RunWith(VertxUnitRunner.class)
public class TokenStoreTest {
  static Vertx vertx;
  static String tenant = "tenantfoo";
  static int port;

  @ClassRule
  public static PostgreSQLContainer<?> postgresSQLContainer = TokenStoreTestContainer.create();;

  // TODO This doesn't work. Get connection refused on the tests in
  // @BeforeClass
  // public static void beforeClass(TestContext context) {
  //   vertx = Vertx.vertx();
  //   port = 9231;
  //   RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
  //   RestAssured.baseURI = "http://localhost:" + port;
  //   RestAssured.requestSpecification = new RequestSpecBuilder().build();
  //   DeploymentOptions deploymentOptions = new DeploymentOptions();
  //   deploymentOptions.setConfig(new JsonObject().put("port", Integer.toString(port)));
  //   vertx.deployVerticle(new MainVerticle(), deploymentOptions)
  //       .onComplete(context.asyncAssertSuccess());
  // }

  // @AfterClass
  // public static void afterClass(TestContext context) {
  //   vertx.close().onComplete(context.asyncAssertSuccess());
  // }

  @Test
  public void anyTest(TestContext c) {}

  // TODO This works when tests are run individually inside the ide (not by) maven. When in maven
  // I get connection refused.
  // @Test
  // public void tenantInit(TestContext context) {
  //   tenantOp(tenant, new JsonObject()
  //       .put("module_to", "mod-mymodule-1.0.0")
  //           .put("parameters", new JsonArray()
  //               .add(new JsonObject().put("key", "loadSample").put("value", "true")))
  //       , null);
  // }

  // void tenantOp(String tenant, JsonObject tenantAttributes, String expectedError) {
  //   ExtractableResponse<Response> response = RestAssured.given()
  //       .header(XOkapiHeaders.TENANT, tenant)
  //       .header(XOkapiHeaders.URL, "http://localhost:" + port)
  //       .header("Content-Type", "application/json")
  //       .body(tenantAttributes.encode())
  //       .post("/_/tenant")
  //       .then()
  //       .extract();

  //   if (response.statusCode() == 204) {
  //     return;
  //   }

  //   System.out.println("Response is " + response.body().asString());

  //   assertThat(response.statusCode(), is(201));
  //   String location = response.header("Location");
  //   JsonObject tenantJob = new JsonObject(response.asString());
  //   assertThat(location, is("/_/tenant/" + tenantJob.getString("id")));

  //   RestAssured.given()
  //       .header(XOkapiHeaders.TENANT, tenant)
  //       .get(location + "?wait=10000")
  //       .then().statusCode(200)
  //       .body("complete", is(true))
  //       .body("error", is(expectedError));

  //   RestAssured.given()
  //       .header(XOkapiHeaders.TENANT, tenant)
  //       .delete(location)
  //       .then().statusCode(204);
  // }
}
