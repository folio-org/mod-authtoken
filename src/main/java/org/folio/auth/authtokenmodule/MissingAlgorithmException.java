package org.folio.auth.authtokenmodule;

public class MissingAlgorithmException extends RuntimeException {
  public MissingAlgorithmException(String message, Exception cause) {
    super(message, cause);
  }
}
