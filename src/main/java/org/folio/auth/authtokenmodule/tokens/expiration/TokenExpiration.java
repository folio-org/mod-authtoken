package org.folio.auth.authtokenmodule.tokens.expiration;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.util.HashMap;

public class TokenExpiration {
  public static final String TOKEN_EXPIRATION_SECONDS = "token.expiration.seconds";

  public static final String TOKEN_EXPIRATION_SECONDS_ENV = "TOKEN_EXPIRATION_SECONDS";

  public static final String MISCONFIGURED_INVALID_ENTRY = "Expected a key value pair with a single colon but found ";

  public static final String MISCONFIGURED_UNKNOWN_KEY = "Token expiration configuration has an unknown key of ";

  private final HashMap<String, TokenExpirationConfiguration> tokenConfiguration;

  public TokenExpiration() {
    tokenConfiguration = new HashMap<>();

    var configuration = getExpirationConfigFromEnvOrSystemProperty();
    if (configuration != null) {
      parseExpirationConfig(configuration);
    }

    tryAddDefaultConfiguration();
  }

  public long getAccessTokenExpiration(String tenant) {
    var tenantConfiguration = tokenConfiguration.get(tenant);
    return (tenantConfiguration == null) ? getDefaultConfiguration().accessTokenExpirationSeconds() :
        tenantConfiguration.accessTokenExpirationSeconds();
  }

  public long getRefreshTokenExpiration(String tenant) {
    var tenantConfiguration = tokenConfiguration.get(tenant);
    return (tenantConfiguration == null) ? getDefaultConfiguration().refreshTokenExpirationSeconds() :
      tenantConfiguration.refreshTokenExpirationSeconds();
  }

  private TokenExpirationConfiguration getDefaultConfiguration() {
    return tokenConfiguration.get(null);
  }

  private void tryAddDefaultConfiguration() {
    tokenConfiguration.putIfAbsent(null,
        new TokenExpirationConfiguration(
            AccessToken.DEFAULT_EXPIRATION_SECONDS,
            RefreshToken.DEFAULT_EXPIRATION_SECONDS));
  }

  private void parseExpirationConfig(String tokenExpirationConfig) {
    var configEntries = tokenExpirationConfig.replace(" ", "").split(";");
    for (String configEntry : configEntries) {
      String tenantId = null;
      long accessTokenExpiration = 0;
      long refreshTokenExpiration = 0;

      String[] keyValuePairs = configEntry.split(",");
      for (String keyValuePair : keyValuePairs) {
        String[] keyValue = keyValuePair.split(":");
        if (keyValue.length != 2) {
          throw new TokenExpirationConfigurationException(MISCONFIGURED_INVALID_ENTRY + keyValuePair);
        }

        String key = keyValue[0];
        String value = keyValue[1];

        switch (key) {
          case "tenantId" -> tenantId = value;
          case "refreshToken" -> refreshTokenExpiration = Long.parseLong(value);
          case "accessToken" -> accessTokenExpiration = Long.parseLong(value);
          default -> throw new TokenExpirationConfigurationException(MISCONFIGURED_UNKNOWN_KEY + key);
        }
      }

      if (accessTokenExpiration <= 0) {
        accessTokenExpiration = AccessToken.DEFAULT_EXPIRATION_SECONDS;
      }

      if (refreshTokenExpiration <=0) {
        refreshTokenExpiration = RefreshToken.DEFAULT_EXPIRATION_SECONDS;
      }

      tokenConfiguration.put(tenantId,
          new TokenExpirationConfiguration(accessTokenExpiration, refreshTokenExpiration));
    }
  }

  private String getExpirationConfigFromEnvOrSystemProperty() {
    var prop = System.getProperty(TOKEN_EXPIRATION_SECONDS);
    if (prop != null) {
      return prop;
    }
    return System.getenv(TOKEN_EXPIRATION_SECONDS_ENV);
  }
}
