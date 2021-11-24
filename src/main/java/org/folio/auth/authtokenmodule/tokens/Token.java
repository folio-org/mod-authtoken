package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.BadSignatureException;
import org.folio.auth.authtokenmodule.TokenCreator;

import java.text.ParseException;

public abstract class Token {

  protected JsonObject claims;
  protected String source;

  static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  public abstract Future<Void> validate();

  protected void validateCommon() throws TokenValidationException {

    // Check that the token has a source.
    if (source == null)
      throw new TokenValidationException("Token has no source defined");
    
    // Check that the token is parsable and signed.
    final String invalidTokenMsg = "Invalid token"; // Be intentionally vague.
    try {
      // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
      var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
      tc.checkJWTToken(source);      
    } catch (ParseException p) {
      throw new TokenValidationException(invalidTokenMsg, p);
    } catch (JOSEException j) {
      throw new TokenValidationException(invalidTokenMsg, j);
    } catch (BadSignatureException b) {
      throw new TokenValidationException(invalidTokenMsg, b);
    }

    // Check that the claims have been created.
    if (claims == null)
      throw new TokenValidationException("Token has no claims");

    // Check some claims that all tokens must have.
    String[] requiredClaims = new String[] { "sub", "tenant", "type" };
    for (String c : requiredClaims) {
      if (!claims.containsKey(c)) {
        throw new TokenValidationException(String.format("Token is missing %s claim", c));
      }
    }
  }

  public String encode() throws JOSEException, ParseException {
    // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
    String key = System.getProperty("jwt.signing.key");
    String encodedClaims = claims.encode();
    return new TokenCreator(key).createJWTToken(encodedClaims);
  }
}
