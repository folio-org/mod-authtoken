package org.folio.auth.authtokenmodule.tokens;

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
