package org.folio.auth.authtokenmodule;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.text.ParseException;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
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
    var at = new AccessToken(tenant, username, userUUID);
    String key = System.getProperty("jwt.signing.key");
    var tokenCreator = new TokenCreator(key);
    var encoded = at.encodeAsJWT(tokenCreator);

    Future<Token> result = Token.validate(encoded, tokenCreator, null);

    assertTrue(result.succeeded());
    result.onSuccess(token -> {
      assertTrue(token instanceof AccessToken);
    });
  }

  @Test
  public void accessTokenIsInvalidTest() throws JOSEException, ParseException, TokenValidationException {
    String tokenMissingTenantClaim =
      "{\"iat\":1637696002,\"sub\":\"test-username\",\"user_id\":\"007d31d2-1441-4291-9bb8-d6e2c20e399a\",\"type\":\"access\"}";
    String key = System.getProperty("jwt.signing.key");
    var tokenCreator = new TokenCreator(key);
    String source = tokenCreator.createJWTToken(tokenMissingTenantClaim);
    
    Future<Token> result = Token.validate(source, tokenCreator, null);

    assert(result.failed());
    result.onFailure(e -> {
      assertTrue(e instanceof TokenValidationException);
      var tve = (TokenValidationException)e;
      assertTrue(tve.httpResponseCode == 500);
    });
  }

  @Test
  public void tokenIsEncryptedTest() throws TokenValidationException, JOSEException, ParseException {
    String key = System.getProperty("jwt.signing.key");
    var tokenCreator = new TokenCreator(key);
    String unencryptedToken =
      new AccessToken("test-tenant", "username-1", "userid-1").encodeAsJWT(tokenCreator);
    String encryptedToken =
      new RefreshToken("test-tenant", "username-1", "userid-1", "http://localhost").encodeAsJWE(tokenCreator);

    assertTrue(Token.isEncrypted(encryptedToken));
    assertFalse(Token.isEncrypted(unencryptedToken));
  }
}