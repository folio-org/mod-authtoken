package org.folio.auth.authtokenmodule.tokens;

/**
 * When a token is provided and it hasn't passed validation, for any reason,
 * a TokenValidationException will be present. Token validation exceptions have
 * an opinion about what http response code should be returned to clients.
 */
public class TokenValidationException extends Exception {
  private final int httpResponseCode;

  /**
   * Returns the HTTP response code to return when this exception is encountered.
   * @return The HTTP response code.
   */
  public int getHttpResponseCode() {
    return httpResponseCode;
  }

  public TokenValidationException(String message, int httpResponseCode) {
    super(message);
    this.httpResponseCode = httpResponseCode;
  }

  public TokenValidationException(String message, Exception cause, int httpResponseCode) {
    super(message, cause);
    this.httpResponseCode = httpResponseCode;
  }

  @Override
  public String toString() {
    if (getCause() != null) {
      return String.format("TokenValidationException: %s %s", getMessage(), getCause().getClass());
    }

    return String.format("TokenValidationException: %s", getMessage());
  }

}
