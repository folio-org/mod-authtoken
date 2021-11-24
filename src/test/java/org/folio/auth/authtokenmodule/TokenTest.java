package org.folio.auth.authtokenmodule;

import java.text.ParseException;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenFactory;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;
import org.junit.Before;
import org.junit.Test;
import io.vertx.core.Future;

public class TokenTest {
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String passPhrase = "CorrectBatteryHorseStaple";
  private static String tenant = "test-abc";
  private static String username = "test-username";

  @Before
  public void setSigningKey() {
    System.setProperty("jwt.signing.key", passPhrase);
  }
 
  @Test
  public void accessTokenIsValidTest() throws JOSEException, ParseException, TokenValidationException {
    // Create an AT and encode it.
    var at = new AccessToken(tenant, username, userUUID);
    var encoded = at.encode();

    // Simulate receving an encoded token for validation.
    Token t = TokenFactory.parseTokenType(encoded);
    Future<Void> r = t.validate();

    assert(r.succeeded());
  }

  @Test
  public void accessTokenIsInvalidTest() throws JOSEException, ParseException, TokenValidationException {
    String tokenMissingTenantClaim =
      "{\"iat\":1637696002,\"sub\":\"test-username\",\"user_id\":\"007d31d2-1441-4291-9bb8-d6e2c20e399a\",\"type\":\"access\"}";
    String key = System.getProperty("jwt.signing.key");
    var source = new TokenCreator(key).createJWTToken(tokenMissingTenantClaim);
    
    Token t = TokenFactory.parseTokenType(source);
    Future<Void> r = t.validate();

    assert(r.failed());
  }

}