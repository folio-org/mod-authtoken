package org.folio.auth.authtoken_module;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;

import io.vertx.core.DeploymentOptions;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

@RunWith(VertxUnitRunner.class)
public class MainVerticleTest {

  @Test
  public void failStartOnInvalidAlgorithm(TestContext context) {
    Vertx.vertx().deployVerticle(MainVerticleInvalidAlgorithm.class, new DeploymentOptions(),
        context.asyncAssertFailure(fail -> assertThat(fail.getMessage(), containsString("TokenCreator"))));
  }

}

