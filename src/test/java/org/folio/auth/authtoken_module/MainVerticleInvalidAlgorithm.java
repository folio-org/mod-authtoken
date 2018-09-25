package org.folio.auth.authtoken_module;

import org.folio.auth.authtokenmodule.MainVerticle;
import org.folio.auth.authtokenmodule.TokenCreator;

import com.nimbusds.jose.JOSEException;

public class MainVerticleInvalidAlgorithm extends MainVerticle {
  @Override
  protected TokenCreator getTokenCreator() throws JOSEException {
    TokenCreator tokenCreator = super.getTokenCreator();
    tokenCreator.setJweHeader(null);
    return tokenCreator;
  }
}
