package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.expiration.TokenExpiration;
import org.folio.auth.authtokenmodule.tokens.expiration.TokenExpirationConfigurationException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class TokenExpirationConfigTest {

  @BeforeEach
  @AfterEach
  public void clearSystemProperty() {
    System.clearProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS);
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "tenantId:abc,accessToken:1000,refreshToken:100000;tenantId:123,accessToken:2000,refreshToken:200000;accessToken:3000,refreshToken:300000",
    "refreshToken:300000,accessToken:3000;refreshToken:200000,accessToken:2000,tenantId:123;refreshToken:100000,accessToken:1000,tenantId:abc",
    "refreshToken:300000, accessToken:3000; refreshToken: 200000, accessToken: 2000, tenantId: 123; refreshToken: 100000, accessToken:1000, tenantId: abc;"})
  void tokenExpirationTenantConfigTest(String config) {
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("abc"), is(1000L));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(100000L));

    assertThat(expiration.getAccessTokenExpiration("123"), is(2000L));
    assertThat(expiration.getRefreshTokenExpiration("123"), is(200000L));

    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(300000L));
  }

  @Test
  void tokenExpirationTenantConfigTestNoAccessOrRefreshSet() {
    String config = "tenantId:abc,refreshToken:100000;tenantId:123,accessToken:1000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("abc"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(100000L));

    assertThat(expiration.getAccessTokenExpiration("123"), is(1000L));
    assertThat(expiration.getRefreshTokenExpiration("123"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));

    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @Test
  void tokenExpirationTenantConfigTestIncorrectValuesToDefault() {
    String config = "tenantId:abc,accessToken:0,refreshToken:0;" +
      "tenantId:123,accessToken:0,refreshToken:-1;" +
      "accessToken:-1,refreshToken:0";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("abc"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));

    assertThat(expiration.getAccessTokenExpiration("123"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("123"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));

    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @Test
  void tokenExpirationOnlyDefaultConfigTest() {
    String config = "accessToken:3000,refreshToken:300000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(300000L));
  }

  @Test
  void tokenExpirationNoConfigTest() {
    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @Test
  void tokenExpirationNoRefreshTest() {
    String config = "accessToken:1000;tenantId:abc,accessToken:2000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(1000L));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getAccessTokenExpiration("abc"), is(2000L));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @Test
  void tokenExpirationNoAccessTest() {
    String config = "tenantId:abc,refreshToken:10000;refreshToken:20000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(10000L));
    assertThat(expiration.getAccessTokenExpiration("abc"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(20000L));
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @Test
  void tokenExpirationNoDefaultTest() {
    String config = "tenantId:123,accessToken:2000,refreshToken:200000;tenantId:abc,accessToken:3000,refreshToken:300000";
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    var expiration = new TokenExpiration();
    assertThat(expiration.getAccessTokenExpiration("123"), is(2000L));
    assertThat(expiration.getRefreshTokenExpiration("123"), is(200000L));
    assertThat(expiration.getAccessTokenExpiration("abc"), is(3000L));
    assertThat(expiration.getRefreshTokenExpiration("abc"), is(300000L));
    assertThat(expiration.getAccessTokenExpiration("anyTenant"), is(AccessToken.DEFAULT_EXPIRATION_SECONDS));
    assertThat(expiration.getRefreshTokenExpiration("anyTenant"), is(RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "unknownKey:abc,accessToken:1,refreshToken:1;accessToken:1,refreshToken:1",
    "tenantId:abc,accessToken:1,unknownKey:1;accessToken:1",
    "tenantId:abc,accessToken:1,refreshToken:1;unknownKey:1" })
  void tokenExpirationMisconfigurationUnknownKeyTest(String config) {
    testThrows(config, TokenExpiration.MISCONFIGURED_UNKNOWN_KEY + "unknownKey");
  }

  @ParameterizedTest
  @ValueSource(strings = { "", ",accessToken", " ,refreshToken", ", tenantId:abc", "tenantId:abc,,accessToken:1"})
  void tokenExpirationMisconfigurationEmptyString(String config) {
    testThrows(config, TokenExpiration.MISCONFIGURED_EMPTY_KEY_VALUE_PAIR);
  }

  @ParameterizedTest
  @ValueSource(strings = { "tenantId:abc:accessToken", "abc", "accessToken", "refreshToken", ":" })
  void tokenExpirationMisconfigurationInvalidEntryTest(String config) {
    testThrows(config, TokenExpiration.MISCONFIGURED_INVALID_ENTRY + config);
  }

  private void testThrows(String config, String message) {
    System.setProperty(TokenExpiration.TOKEN_EXPIRATION_SECONDS, config);

    Throwable t = Assertions.assertThrows(TokenExpirationConfigurationException.class, TokenExpiration::new);
    assertThat(t.getMessage(), is(message));
  }
}
