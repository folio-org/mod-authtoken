package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.ttl.TokenTTL;
import org.folio.auth.authtokenmodule.tokens.ttl.TokenTTLConfigurationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenTTLConfigTest {

  @Before
  public void setUp() {
    TokenTTL.resetInstance(); // Reset the Singleton instance before each test
  }

  @Test
  public void tokenTtlTenantConfigTest() {
    String config = "tenantId:testTenant1,accessToken:1000,refreshToken:100000;" +
      "tenantId:testTenant2,accessToken:2000,refreshToken:200000;" +
      "accessToken:3000,refreshToken:300000";

    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    var ttl = TokenTTL.getInstance();
    assertThat(ttl.getAccessTokenTll("testTenant1"), is(1000L));
    assertThat(ttl.getRefreshTokenTtl("testTenant1"), is(100000L));

    assertThat(ttl.getAccessTokenTll("testTenant2"), is(2000L));
    assertThat(ttl.getRefreshTokenTtl("testTenant2"), is(200000L));

    assertThat(ttl.getAccessTokenTll("anyTenant"), is(3000L));
    assertThat(ttl.getRefreshTokenTtl("anyTenant"), is(300000L));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }

  @Test
  public void tokenTtlOnlyDefaultConfigTest() {
    String config = "accessToken:3000,refreshToken:300000";

    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    var ttl = TokenTTL.getInstance();

    assertThat(ttl.getAccessTokenTll("anyTenant"), is(3000L));
    assertThat(ttl.getRefreshTokenTtl("anyTenant"), is(300000L));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }

  @Test
  public void tokenTtlNoConfigTest() {
    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);

    var ttl = TokenTTL.getInstance();

    assertThat(ttl.getAccessTokenTll("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(ttl.getRefreshTokenTtl("anyTenant"), is(RefreshToken.DEFALUT_EXPIRATION_SECONDS));
  }

  @Test
  public void tokenTtlMisconfigurationTenant() {
    String config = "tenantIdBroken:abc,accessToken:3000,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_TENANT);
  }

  @Test
  public void tokenTtlMisconfigurationAccessToken() {
    String config = "tenantIdBroken:abc,accessTokenMisspelled:3000,refreshToken:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_AT);
  }

  @Test
  public void tokenTtlMisconfigurationRefreshToken() {
    String config = "tenantId:abc,accessToken:3000,refreshTokenMisspelled:300000;" +
      "accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_RT);
  }

  @Test
  public void tokenTtlMisconfigurationNoDefault() {
    String config = "tenantId:abc,accessToken:3000,refreshToken:300000";
    testThrows(config, TokenTTL.MISCONFIGURED_NO_DEFAULT);
  }

  @Test
  public void tokenTtlMisconfigurationMissingSeparator() {
    String config1 = "tenantId,abc,accessToken";
    testThrows(config1, TokenTTL.MISCONFIGURED_MISSING_SEPARATOR);

    String config2 = "tenantId:abc:accessToken";
    testThrows(config2, TokenTTL.MISCONFIGURED_MISSING_SEPARATOR);
  }

  private void testThrows(String config, String message) {
    System.setProperty(TokenTTL.TOKEN_TTL_CONFIG, config);

    Throwable t = Assert.assertThrows(TokenTTLConfigurationException.class, TokenTTL::getInstance);
    assertThat(t.getMessage(), is(message));

    System.clearProperty(TokenTTL.TOKEN_TTL_CONFIG);
  }
}
