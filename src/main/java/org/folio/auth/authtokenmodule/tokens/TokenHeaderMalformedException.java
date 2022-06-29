package org.folio.auth.authtokenmodule.tokens;

/**
 * Thrown when a token doesn't arrive in one of the following headers or is present in
 * more than one:
 * - X-Okapi-Token
 * - Authorization Bearer
 * - Cookie: accessToken=abc123
 */
public class TokenHeaderMalformedException extends Exception {
    public TokenHeaderMalformedException(String message) {
    super(message);
  }
}
