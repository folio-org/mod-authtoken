package org.folio.auth.authtokenmodule.tokens.expiration;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.util.HashMap;

public class TokenExpiration {
  public static final String TOKEN_EXPIRATION_CONFIG = "token.expiration.config";

  public static final String TOKEN_EXPIRATION_CONFIG_ENV = "TOKEN_EXPIRATION_CONFIG";

  public static final String MISCONFIGURED_TENANT = "Tenant expected in token Expiration configuration";

  public static final String MISCONFIGURED_INCORRECT_VALUE = "Token expiration configuration has an incorrect value";

  public static final String MISCONFIGURED_MISSING_SEPARATOR = "Token expiration configuration is missing at least one separator";

  public static final String MISCONFIGURED_INVALID_ENTRY = "Token expiration configuration has an invalid entry";

  public static final String MISCONFIGURED_UNKNOWN_KEY = "Token expiration configuration has an unknown key";

  public TokenExpiration() {
    tenantTokenConfiguration = new HashMap<>();

    String tokenExpirationConfiguration = getExpirationConfig();

    if (tokenExpirationConfiguration == null) {
      defaultExpirationConfiguration = new TokenExpirationConfiguration(AccessToken.DEFAULT_EXPIRATION_SECONDS,
                                                                        RefreshToken.DEFALUT_EXPIRATION_SECONDS);
    } else {
      parseExpirationConfig(tokenExpirationConfiguration);
    }
  }

  public long getAccessTokenExpiration(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.accessTokenExpirationSeconds();
    }
    return defaultExpirationConfiguration.accessTokenExpirationSeconds();
  }

  public long getRefreshTokenExpiration(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.refreshTokenExpirationSeconds();
    }
    return defaultExpirationConfiguration.refreshTokenExpirationSeconds();
  }

  private TokenExpirationConfiguration defaultExpirationConfiguration;

  private final HashMap<String, TokenExpirationConfiguration> tenantTokenConfiguration;

  private void parseExpirationConfig(String tokenExpirationConfig) {
    if (!tokenExpirationConfig.contains(":") || !tokenExpirationConfig.contains(","))
      throw new TokenExpirationConfigurationException(MISCONFIGURED_MISSING_SEPARATOR);

    var configEntries = tokenExpirationConfig.replace(" ", "").split(";");
    for (String configEntry : configEntries) {
      String tenantId = null;
      long accessTokenExpiration = 0;
      long refreshTokenExpiration = 0;

      String[] keyValuePairs = configEntry.split(",");
      for (String keyValuePair : keyValuePairs) {
        String[] keyValue = keyValuePair.split(":");
        if (keyValue.length != 2) {
          throw new TokenExpirationConfigurationException(MISCONFIGURED_INVALID_ENTRY);
        }

        String key = keyValue[0];
        String value = keyValue[1];

        switch (key) {
          case "tenantId" -> tenantId = value;
          case "refreshToken" -> refreshTokenExpiration = Long.parseLong(value);
          case "accessToken" -> accessTokenExpiration = Long.parseLong(value);
          default -> throw new TokenExpirationConfigurationException(MISCONFIGURED_UNKNOWN_KEY);
        }
      }

      if (accessTokenExpiration <= 0 || refreshTokenExpiration <= 0)
        throw new TokenExpirationConfigurationException(MISCONFIGURED_INCORRECT_VALUE);

      if (keyValuePairs.length == 3 && tenantId == null)
        throw new TokenExpirationConfigurationException(MISCONFIGURED_TENANT);

      if (tenantId != null) {
        tenantTokenConfiguration.put(tenantId, new TokenExpirationConfiguration(accessTokenExpiration, refreshTokenExpiration));
      } else {
        defaultExpirationConfiguration = new TokenExpirationConfiguration(accessTokenExpiration, refreshTokenExpiration);
      }
    }

    if (defaultExpirationConfiguration == null)
      defaultExpirationConfiguration = new TokenExpirationConfiguration(AccessToken.DEFAULT_EXPIRATION_SECONDS,
                                                                        RefreshToken.DEFALUT_EXPIRATION_SECONDS);
  }

  private String getExpirationConfig() {
    var prop = System.getProperty(TOKEN_EXPIRATION_CONFIG);
    if (prop != null) {
      return prop;
    }
    return System.getenv(TOKEN_EXPIRATION_CONFIG_ENV);
  }
}
