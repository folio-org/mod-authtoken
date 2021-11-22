package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;

import java.text.ParseException;

public abstract class Token {

  protected JsonObject claims;
  protected String source;

  static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  abstract Future<TokenValidationResult> isValid();

  protected TokenValidationResult validateCommon() {
    // Check that the token has a source.
    if (source == null)
      return new TokenValidationResult("Token has no source defined", 400);
    
    // Check that the token is parsable and signed.
    final String invalidTokenMsg = "Invalid token"; // Be intentionally vague.
    try {
      // TODO Should the TokenCreator be passed in as an arg?
      var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
      tc.checkJWTToken(source);      
    } catch (ParseException p) {
      return new TokenValidationResult(invalidTokenMsg, 401);
    } catch (JOSEException j) {
      return new TokenValidationResult(invalidTokenMsg, 401);
    } catch (BadSignatureException b) {
      return new TokenValidationResult(invalidTokenMsg, 401);
    }

    // Check that the claims have been created.
    if (claims == null)
      return new TokenValidationResult("Token has no claims", 400);

    // Check some claims that all tokens must have.
    String[] coreClaims = new String[] { "sub", "tenant", "type" };
    for (String c : coreClaims) {
      if (!claims.containsKey(c)) {
        return new TokenValidationResult(String.format("Token is missing %s claim", c), 400);
      }
    }

    // All is well, return that the items common to all tokens have completed successfully.
    return TokenValidationResult.success();
  }

  public String encode() throws JOSEException {
    String key = System.getProperty("jwt.signing.key");
      // TODO Should the TokenCreator be passed in as an arg?
      return new TokenCreator(key).createJWEToken(claims.encode());
  }
}
