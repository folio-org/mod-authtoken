package org.folio.auth.authtokenmodule.tokens;

/**
 * When a token is provided and it hasn't passed validation, for any reason,
 * a TokenValidationException will be present. Token validation exceptions have
 * an opinion about what http response code should be returned to clients.
 */
public class TokenValidationException extends Exception {
  public int httpResponseCode;

  public TokenValidationException(String message, int responseCode) {
    super(message);
    httpResponseCode = responseCode;
  }

  public TokenValidationException(String message, Exception cause, int responseCode) {
    super(message, cause);
    httpResponseCode = responseCode;
  }

  @Override
  public String toString() {
    if (getCause() != null)
      return String.format("TokenValidationException: %s %s", getMessage(), getCause().getClass());

    return String.format("TokenValidationException: %s", getMessage());
  }

}
