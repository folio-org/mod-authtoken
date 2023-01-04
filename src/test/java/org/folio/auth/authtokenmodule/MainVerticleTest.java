package org.folio.auth.authtokenmodule;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import com.nimbusds.jose.JOSEException;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.json.JsonObject;
import org.apache.logging.log4j.Level;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.vertx.core.Vertx;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class MainVerticleTest {
  @Test
  public void deployAndUndeploy(TestContext context) {
    Vertx vertx = Vertx.vertx();
    vertx.deployVerticle(MainVerticle.class.getName(),
        new DeploymentOptions().setConfig(
            new JsonObject().put("port", NetworkUtils.nextFreePort())
        ),
        context.asyncAssertSuccess(run -> vertx.close(context.asyncAssertSuccess())));
  }

  @Test
  public void failStartOnInvalidAlgorithm(TestContext context) {
    class MainVerticleInvalidAlgorithm extends MainVerticle {
      @Override
      TokenCreator getTokenCreator() throws JOSEException {
        TokenCreator tokenCreator = super.getTokenCreator();
        tokenCreator.setJweHeader(null);
        return tokenCreator;
      }
    }

    Vertx.vertx().deployVerticle(new MainVerticleInvalidAlgorithm(),
         context.asyncAssertFailure(fail ->
         assertThat(fail, is(instanceOf(MissingAlgorithmException.class)))));
  }

  @Test
  public void setLogLevel(TestContext context) {
    Level old = MainVerticle.setLogLevel(Level.ERROR);
    MainVerticle.setLogLevel("info");
    Level last = MainVerticle.setLogLevel(old);
    context.assertEquals(Level.INFO, last);
  }
}
