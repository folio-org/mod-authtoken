package org.folio.auth.authtokenmodule;

public class TokenValidationException extends Exception {
  public TokenValidationException(String message) {
    super(message);
  }

  public TokenValidationException(String message, Exception cause) {
    super(message, cause);
  }

  @Override
  public String toString() {
    return String.format("TokenValidationException: %s %s", getMessage(), getCause().getClass());
  }

}
