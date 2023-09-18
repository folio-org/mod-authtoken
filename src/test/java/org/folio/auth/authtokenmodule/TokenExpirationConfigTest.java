package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.expiration.TokenExpiration;
import org.folio.auth.authtokenmodule.tokens.expiration.TokenExpirationConfigurationException;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenExpirationConfigTest {

  @Test
  public void tokenExpirationTenantConfigTest() {
    String config = "tenantId:testTenant1,accessToken:1000,refreshToken:100000;" +
      "tenantId:testTenant2,accessToken:2000,refreshToken:200000;" +
      "accessToken:3000,refreshToken:300000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("testTenant1"), is(1000L));
    assertThat(expiration.getRefreshTokenExpiration("testTenant1"), is(100000L));

    assertThat(expiration.getAccessTokenExpiration("testTenant2"), is(2000L));
    assertThat(expiration.getRefreshTokenExpiration("testTenant2"), is(200000L));

    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(300000L));

    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG);
  }

  @Test
  public void tokenExpirationOnlyDefaultConfigTest() {
    String config = "accessToken:3000,refreshToken:300000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(300000L));

    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG);
  }

  @Test
  public void tokenExpirationNoConfigTest() {
    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFALUT_EXPIRATION_SECONDS));
  }

  @Test
  public void tokenExpirationMisconfigurationNoDefault() {
    String config = "tenantId:abc,accessToken:3000,refreshToken:300000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("abc"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(300000L));
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFALUT_EXPIRATION_SECONDS));

    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG);
  }

  @Test
  public void tokenExpirationMisconfigurationUnknownKey() {
    String config = "tenantIdUnknown:abc,accessToken:3000,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenExpiration.MISCONFIGURED_UNKNOWN_KEY);
  }

  @Test
  public void tokenExpirationMisconfigurationRefreshToken() {
    String config = "tenantId:abc,accessToken:0,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenExpiration.MISCONFIGURED_INCORRECT_VALUE);
  }

  @Test
  public void tokenExpirationMisconfigurationMissingSeparator() {
    String config1 = "tenantId,abc,accessToken";
    testThrows(config1, TokenExpiration.MISCONFIGURED_MISSING_SEPARATOR);

    String config2 = "tenantId:abc:accessToken";
    testThrows(config2, TokenExpiration.MISCONFIGURED_MISSING_SEPARATOR);
  }

  private void testThrows(String config, String message) {
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG, config);

    Throwable t = Assert.assertThrows(TokenExpirationConfigurationException.class, TokenExpiration::new);
    assertThat(t.getMessage(), is(message));

    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_CONFIG);
  }
}
