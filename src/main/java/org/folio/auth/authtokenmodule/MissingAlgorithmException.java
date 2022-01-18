package org.folio.auth.authtokenmodule;

public class MissingAlgorithmException extends Exception {
  public MissingAlgorithmException(String message, Exception cause) {
    super(message, cause);
  }
}
