package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;

public abstract class Token {

  protected JsonObject claims;

  protected JsonObject getClaims() {
    return claims;
  }

  static JsonObject setClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  public static String getTokenType(String jwt) {
    return setClaims(jwt).getString("type");
  }

  // Each of our token types has slightly different validation logic,
  // yet callers should not have to know about this or even know what type
  // of token we are validating.
  abstract Future<Boolean> isValid();

  public String encode() throws JOSEException {
    String key = System.getProperty("jwt.signing.key");
    return new TokenCreator(key).createJWEToken(claims.encode());
  }
}