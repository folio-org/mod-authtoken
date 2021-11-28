package org.folio.auth.authtokenmodule;

import java.text.ParseException;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.Token;
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
    var encoded = at.encodeAsJWT();

    Future<Token> result = Token.validate(encoded, null);

    assert(result.succeeded());
    result.onSuccess(token -> {
      assert(token instanceof AccessToken);
    });
  }

  @Test
  public void accessTokenIsInvalidTest() throws JOSEException, ParseException, TokenValidationException {
    String tokenMissingTenantClaim =
      "{\"iat\":1637696002,\"sub\":\"test-username\",\"user_id\":\"007d31d2-1441-4291-9bb8-d6e2c20e399a\",\"type\":\"access\"}";
    String key = System.getProperty("jwt.signing.key");
    String source = new TokenCreator(key).createJWTToken(tokenMissingTenantClaim);
    
    Future<Token> result = Token.validate(source, null);

    assert(result.failed());
    result.onFailure(e -> {
      assert(e instanceof TokenValidationException);
      var tve = (TokenValidationException)e;
      assert(tve.httpResponseCode == 500);
    });
  }

}