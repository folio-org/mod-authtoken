package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.BadSignatureException;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.okapi.common.XOkapiHeaders;

import java.text.ParseException;

public abstract class Token {

  protected JsonObject claims;
  protected String source;

  public static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  public abstract Future<Void> validate(MultiMap headers);

  protected void validateCommon(MultiMap headers) throws TokenValidationException {

    // Check that the token has a source.
    if (source == null)
      throw new TokenValidationException("Token has no source defined", 500);

    // Check that the token is parsable and signed.
    final String invalidTokenMsg = "Invalid token"; // Be intentionally vague.
    try {
      // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
      var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
      tc.checkJWTToken(source);
    } catch (ParseException p) {
      throw new TokenValidationException(invalidTokenMsg, p, 401);
    } catch (JOSEException j) {
      throw new TokenValidationException(invalidTokenMsg, j, 401);
    } catch (BadSignatureException b) {
      throw new TokenValidationException(invalidTokenMsg, b, 401);
    }

    // Check that the claims have been created.
    if (claims == null)
      throw new TokenValidationException("Token has no claims", 500);

    // Check some claims that all tokens must have.
    String[] requiredClaims = new String[] { "sub", "tenant", "type" };
    for (String c : requiredClaims) {
      if (!claims.containsKey(c)) {
        throw new TokenValidationException(String.format("Token is missing %s claim", c), 500);
      }
    }

    if (headers == null)
      return;

    // Check that some items in the headers match what are in the token.
    String headerTenant = headers.get(XOkapiHeaders.TENANT);
    if (!claims.getString("tenant").equals(headerTenant))
      throw new TokenValidationException("Tenant in header does not equal tenant in token", 403);

    String headerUserId = headers.get(XOkapiHeaders.USER_ID);
    if (headerUserId != null && !claims.getString("user_id").equals(headerUserId))
      throw new TokenValidationException("User id in header does not equal userid in token", 403);
  }

  public String encodeAsJWT() throws JOSEException, ParseException {
    // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
    String key = System.getProperty("jwt.signing.key");
    String encodedClaims = claims.encode();
    return new TokenCreator(key).createJWTToken(encodedClaims);
  }

  public String encodeAsJWE() throws JOSEException, ParseException {
    // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
    String key = System.getProperty("jwt.signing.key");
    String encodedClaims = claims.encode();
    return new TokenCreator(key).createJWEToken(encodedClaims);
  }
}
