package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.ttl.TokenTTL;
import org.folio.auth.authtokenmodule.tokens.ttl.TokenTTLConfigurationException;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenTTLConfigTest {

  @Test
  public void tokenTTLTenantConfigTest() {
    String config = "tenantId:testTenant1,accessToken:1000,refreshToken:100000;" +
      "tenantId:testTenant2,accessToken:2000,refreshToken:200000;" +
      "accessToken:3000,refreshToken:300000";

    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    var ttl = new TokenTTL();
    assertThat(ttl.getAccessTokenTTL("testTenant1"), is(1000L));
    assertThat(ttl.getRefreshTokenTTL("testTenant1"), is(100000L));

    assertThat(ttl.getAccessTokenTTL("testTenant2"), is(2000L));
    assertThat(ttl.getRefreshTokenTTL("testTenant2"), is(200000L));

    assertThat(ttl.getAccessTokenTTL("anyTenant"), is(3000L));
    assertThat(ttl.getRefreshTokenTTL("anyTenant"), is(300000L));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }

  @Test
  public void tokenTTLOnlyDefaultConfigTest() {
    String config = "accessToken:3000,refreshToken:300000";

    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    var ttl = new TokenTTL();

    assertThat(ttl.getAccessTokenTTL("anyTenant"), is(3000L));
    assertThat(ttl.getRefreshTokenTTL("anyTenant"), is(300000L));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }

  @Test
  public void tokenTTLNoConfigTest() {
    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);

    var ttl = new TokenTTL();

    assertThat(ttl.getAccessTokenTTL("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(ttl.getRefreshTokenTTL("anyTenant"), is(RefreshToken.DEFALUT_EXPIRATION_SECONDS));
  }

  @Test
  public void tokenTTLMisconfigurationNoDefault() {
    String config = "tenantId:abc,accessToken:3000,refreshToken:300000";
    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);
    var ttl = new TokenTTL();
    assertThat(ttl.getAccessTokenTTL("abc"), is(3000L));
    assertThat(ttl.getRefreshTokenTTL("abc"), is(300000L));
    assertThat(ttl.getAccessTokenTTL("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(ttl.getRefreshTokenTTL("anyTenant"), is(RefreshToken.DEFALUT_EXPIRATION_SECONDS));
    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }

  @Test
  public void tokenTTLMisconfigurationUnknownKey() {
    String config = "tenantIdUnknown:abc,accessToken:3000,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_UNKNOWN_KEY);
  }

  @Test
  public void tokenTTLMisconfigurationRefreshToken() {
    String config = "tenantId:abc,accessToken:0,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_INCORRECT_VALUE);
  }

  @Test
  public void tokenTTLMisconfigurationMissingSeparator() {
    String config1 = "tenantId,abc,accessToken";
    testThrows(config1, TokenTTL.MISCONFIGURED_MISSING_SEPARATOR);

    String config2 = "tenantId:abc:accessToken";
    testThrows(config2, TokenTTL.MISCONFIGURED_MISSING_SEPARATOR);
  }

  private void testThrows(String config, String message) {
    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    Throwable t = Assert.assertThrows(TokenTTLConfigurationException.class, TokenTTL::new);
    assertThat(t.getMessage(), is(message));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }
}
