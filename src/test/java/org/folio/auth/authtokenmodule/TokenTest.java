package org.folio.auth.authtokenmodule;

import java.text.ParseException;

import com.nimbusds.jose.JOSEException;

import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.DummyToken;
import org.folio.auth.authtokenmodule.tokens.legacy.LegacyAccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.DummyTokenExpiring;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.auth.authtokenmodule.tokens.TokenValidationException;
import org.folio.okapi.common.XOkapiHeaders;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import io.vertx.core.Future;
import org.mockito.Mockito;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenTest {
  private static String userUUID = "007d31d2-1441-4291-9bb8-d6e2c20e399a";
  private static String passPhrase = "CorrectBatteryHorseStaple";
  private static String tenant = "test-abc";
  private static String username = "test-username";
  private final UserService userService =
    new UserService(Vertx.vertx().getOrCreateContext().owner(), 60, 43200);

  @Before
  public void setSigningKey() {
    System.setProperty("jwt.signing.key", passPhrase);
  }

  @Test
  public void accessTokenIsValidTest() throws JOSEException, ParseException {
    var at = new AccessToken(tenant, username, userUUID, 1);
    var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
    assertTokenIsValid(at.encodeAsJWT(tc), tc, AccessToken.class);
  }

  @Test
  public void dummyExpiringTokenIsValidTest() throws JOSEException, ParseException {
    var dte = new DummyTokenExpiring(tenant, new JsonArray(), "testuser", 1);
    var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
    assertTokenIsValid(dte.encodeAsJWT(tc), tc, DummyTokenExpiring.class);
  }

  @Test
  public void accessTokenMissingTenantClaims() throws JOSEException, ParseException {
    String tokenMissingTenantClaim =
      "{\"iat\":1637696002,\"sub\":\"test-username\",\"user_id\":\"007d31d2-1441-4291-9bb8-d6e2c20e399a\",\"type\":\"access\"}";
    String key = System.getProperty("jwt.signing.key");
    var tokenCreator = new TokenCreator(key);
    String encoded = tokenCreator.createJWTToken(tokenMissingTenantClaim);
    assertTokenIsInvalid(encoded, tokenCreator, 500);
  }

  @Test
  public void accessTokenIsExpiredTest() throws JOSEException, ParseException {
    var at = new AccessToken(tenant, username, userUUID, -1);
    var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
    assertTokenIsInvalid(at.encodeAsJWT(tc), tc,401);
  }

  @Test
  public void dummyTokenExpiringIsExpiredTest() throws JOSEException, ParseException {
    var dte = new DummyTokenExpiring(tenant, new JsonArray(), "testuser", -1);
    var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
    assertTokenIsInvalid(dte.encodeAsJWT(tc), tc,401);
  }

  @Test
  public void refreshTokenExpiringIsExpiredTest() throws JOSEException, ParseException {
    var rt = new RefreshToken(tenant, "jones", userUUID, "127.0.0.1", -1);
    var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
    assertTokenIsInvalid(rt.encodeAsJWE(tc), tc,401);
  }

  @Test
  public void tokenIsEncryptedTest() throws TokenValidationException, JOSEException, ParseException {
    String key = System.getProperty("jwt.signing.key");
    var tokenCreator = new TokenCreator(key);
    long defaultAtExpires = AccessToken.DEFAULT_EXPIRATION_SECONDS;
    long defaultRtExpires = RefreshToken.DEFAULT_EXPIRATION_SECONDS;
    String unencryptedToken =
      new AccessToken("test-tenant", "username-1", "userid-1", defaultAtExpires).encodeAsJWT(tokenCreator);
    String encryptedToken =
      new RefreshToken("test-tenant", "username-1", "userid-1", "http://localhost", defaultRtExpires).encodeAsJWE(tokenCreator);

    assertThat(Token.isEncrypted(encryptedToken), is(true));
    assertThat(Token.isEncrypted(unencryptedToken), is(false));
  }

  @Test
  public void noTypeDummy() throws TokenValidationException {
    JsonObject claims = new JsonObject()
      .put("dummy", true)
      .put("tenant", "lib");
    Token parse = Token.parse(".", claims);
    assertThat(parse, is(instanceOf(DummyToken.class)));
  }

  @Test
  public void noTypeLegacyAccess() throws TokenValidationException {
    JsonObject claims = new JsonObject()
      .put("tenant", "lib");
    Token parse = Token.parse(".", claims);
    assertThat(parse, is(instanceOf(LegacyAccessToken.class)));
  }

  @Test
  public void badTypeString() {
    JsonObject claims = new JsonObject()
      .put("type", "foo")
      .put("tenant", "lib");
    Throwable t = Assert.assertThrows(TokenValidationException.class, () -> Token.parse(".", claims));
    assertThat(t.getMessage(), is("Unable to parse token"));
  }

  @Test
  public void badTypeStructure() {
    JsonObject claims = new JsonObject()
      .put("type", 3)
      .put("tenant", "lib");
    Throwable t = Assert.assertThrows(TokenValidationException.class, () -> Token.parse(".", claims));
    assertThat(t.getMessage(), is("Unable to parse token"));
  }

  private void assertTokenIsInvalid(String token, TokenCreator tokenCreator, int errorCode)  throws JOSEException, ParseException {
    MultiMap headers = Mockito.mock(MultiMap.class);
    Mockito.when(headers.get(XOkapiHeaders.USER_ID)).thenReturn(userUUID);
    Mockito.when(headers.get(XOkapiHeaders.TENANT)).thenReturn(tenant);
    HttpServerRequest request = Mockito.mock(HttpServerRequest.class);
    Mockito.when(request.headers()).thenReturn(headers);
    SocketAddress socketAddress = Mockito.mock(SocketAddress.class);
    Mockito.when(request.remoteAddress()).thenReturn(socketAddress);
    Mockito.when(request.remoteAddress().host()).thenReturn("127.0.0.1");

    var context = new TokenValidationContext(request, tokenCreator, token, userService);
    Future<Token> result = Token.validate(context);

    assertThat(result.failed(), is(true));
    assertThat(result.cause(), is(instanceOf(TokenValidationException.class)));
    assertThat(((TokenValidationException) result.cause()).getHttpResponseCode(), is(errorCode));
  }

  private <T> void assertTokenIsValid(String token, TokenCreator tokenCreator, Class<T> clazz) {
    MultiMap headers = Mockito.mock(MultiMap.class);
    Mockito.when(headers.get(XOkapiHeaders.USER_ID)).thenReturn(userUUID);
    Mockito.when(headers.get(XOkapiHeaders.TENANT)).thenReturn(tenant);
    HttpServerRequest request = Mockito.mock(HttpServerRequest.class);
    Mockito.when(request.headers()).thenReturn(headers);
    SocketAddress socketAddress = Mockito.mock(SocketAddress.class);
    Mockito.when(request.remoteAddress()).thenReturn(socketAddress);
    Mockito.when(request.remoteAddress().host()).thenReturn("127.0.0.1");

    var context = new TokenValidationContext(request, tokenCreator, token, userService);
    Future<Token> result = Token.validate(context);

    assertThat(result.succeeded(), is(true));
    assertThat(result.result(), is(instanceOf(clazz)));
  }
}
