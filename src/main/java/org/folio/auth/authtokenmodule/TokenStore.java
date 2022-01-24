package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.Token;

import java.util.List;

import org.apache.commons.lang3.NotImplementedException;

import io.vertx.core.Future;
import io.vertx.core.Vertx;

public class TokenStore {

  private Vertx vertx;

  public TokenStore(Vertx vertx) {
    this.vertx = vertx;

    // TODO implement this to clean up expired tokens from store.
    //vertx.setPeriodic(delay, handler)
  }

  public Future<Void> storeToken(Token t) {
    // TODO Get the tenant from the token claiam.
    throw new NotImplementedException("TODO");
  }

  public Future<Void> setTokenRevoked(Token t) {
    // TODO Get the tenant from the token claiam.
    throw new NotImplementedException("TODO");
  }

  public Future<List<Token>> getTokensManagedByUser(String userId) {
    // TODO Get the tenant from the token claiam.
    throw new NotImplementedException("TODO");
  }

  public Future<Void> checkTokenRevoked(Token t) {
    // TODO Get the tenant from the token claiam.
    throw new NotImplementedException("TODO");
  }

  public Future<Void> cleanupExpiredTokens() {
    // TODO Get the tenant from the token claiam.
    throw new NotImplementedException("TODO");
  }
}
