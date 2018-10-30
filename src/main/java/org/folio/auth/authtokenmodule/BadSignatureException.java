package org.folio.auth.authtokenmodule;

/**
 *
 * @author kurt
 */
public class BadSignatureException extends Exception {
  public BadSignatureException() {
    super();
  }
  public BadSignatureException(String s) {
    super(s);
  }
}
