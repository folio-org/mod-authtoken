package org.folio.auth.authtokenmodule.tokens;

import org.folio.auth.authtokenmodule.TokenCreator;

import io.vertx.core.http.HttpServerRequest;

/**
 * Represents the context in which a token is validated, including any
 * references to items which are needed to validate the token, including items like
 * the http request.
 */
public class TokenValidationContext {
  private HttpServerRequest httpServerRequest;
  private String tokenToValidate;
  private TokenCreator tokenCreator;

  /**
   * Gets the http request associated with the validation context.
   * @return The current http request.
   */
  public HttpServerRequest getHttpServerRequest() {
    return httpServerRequest;
  }

  /**
   * Gets a reference to the token creator object associated with this context.
   * @return The token creator associated with this context.
   */
  public TokenCreator getTokenCreator() {
    return tokenCreator;
  }

  /**
   * Gets a reference to the token which is being validated in this context.
   * @return The token which is being validated in this context.
   */
  public String getTokenToValidate() {
    return tokenToValidate;
  }

  public TokenValidationContext(HttpServerRequest httpServerRequest,
                                TokenCreator tokenCreator,
                                String tokenToValidate) {
    this.httpServerRequest = httpServerRequest;
    this.tokenCreator = tokenCreator;
    this.tokenToValidate = tokenToValidate;
  }
}
