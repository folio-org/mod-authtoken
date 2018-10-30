/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
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
