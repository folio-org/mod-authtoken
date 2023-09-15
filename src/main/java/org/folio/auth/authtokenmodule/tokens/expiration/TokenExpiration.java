package org.folio.auth.authtokenmodule.tokens.ttl;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.util.HashMap;

public class TokenTTL {
  public static final String TOKEN_TTL_CONFIG = "token.ttl.config";

  public static final String TOKEN_TTL_CONFIG_ENV = "TOKEN_TTL_CONFIG";

  public static final String MISCONFIGURED_TENANT = "Tenant expected in token TTL configuration";

  public static final String MISCONFIGURED_INCORRECT_VALUE = "Token TTL configuration has an incorrect value";

  public static final String MISCONFIGURED_MISSING_SEPARATOR = "Token TTL configuration is missing at least one separator";

  public static final String MISCONFIGURED_INVALID_ENTRY = "Token TTL configuration has an invalid entry";

  public static final String MISCONFIGURED_UNKNOWN_KEY = "Token TTL configuration has an unknown key";

  public TokenTTL() {
    tenantTokenConfiguration = new HashMap<>();

    String tokenTTLConfiguration = getTTLConfig();

    if (tokenTTLConfiguration == null) {
      defaultTTLConfiguration = new TokenTTLConfiguration(AccessToken.DEFAULT_EXPIRATION_SECONDS,
        RefreshToken.DEFALUT_EXPIRATION_SECONDS);
    } else {
      parseTTLConfig(tokenTTLConfiguration);
    }
  }

  public long getAccessTokenTTL(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.accessTokenTTLSeconds();
    }
    return defaultTTLConfiguration.accessTokenTTLSeconds();
  }

  public long getRefreshTokenTTL(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.refreshTokenTTLSeconds();
    }
    return defaultTTLConfiguration.refreshTokenTTLSeconds();
  }

  private TokenTTLConfiguration defaultTTLConfiguration;

  private final HashMap<String, TokenTTLConfiguration> tenantTokenConfiguration;

  private void parseTTLConfig(String tokenTTLConfig) {
    if (!tokenTTLConfig.contains(":") || !tokenTTLConfig.contains(","))
      throw new TokenTTLConfigurationException(MISCONFIGURED_MISSING_SEPARATOR);

    var configEntries = tokenTTLConfig.replace(" ", "").split(";");
    for (String configEntry : configEntries) {
      String tenantId = null;
      long accessTokenTTL = 0;
      long refreshTokenTTL = 0;

      String[] keyValuePairs = configEntry.split(",");
      for (String keyValuePair : keyValuePairs) {
        String[] keyValue = keyValuePair.split(":");
        if (keyValue.length != 2) {
          throw new TokenTTLConfigurationException(MISCONFIGURED_INVALID_ENTRY);
        }

        String key = keyValue[0];
        String value = keyValue[1];

        switch (key) {
          case "tenantId" -> tenantId = value;
          case "refreshToken" -> refreshTokenTTL = Long.parseLong(value);
          case "accessToken" -> accessTokenTTL = Long.parseLong(value);
          default -> throw new TokenTTLConfigurationException(MISCONFIGURED_UNKNOWN_KEY);
        }
      }

      if (accessTokenTTL <= 0 || refreshTokenTTL <= 0)
        throw new TokenTTLConfigurationException(MISCONFIGURED_INCORRECT_VALUE);

      if (keyValuePairs.length == 3 && tenantId == null)
        throw new TokenTTLConfigurationException(MISCONFIGURED_TENANT);

      if (tenantId != null) {
        tenantTokenConfiguration.put(tenantId, new TokenTTLConfiguration(accessTokenTTL, refreshTokenTTL));
      } else {
        defaultTTLConfiguration = new TokenTTLConfiguration(accessTokenTTL, refreshTokenTTL);
      }
    }

    if (defaultTTLConfiguration == null)
      defaultTTLConfiguration = new TokenTTLConfiguration(AccessToken.DEFAULT_EXPIRATION_SECONDS,
                                                          RefreshToken.DEFALUT_EXPIRATION_SECONDS);
  }

  private String getTTLConfig() {
    var prop = System.getProperty(TOKEN_TTL_CONFIG);
    if (prop != null) {
      return prop;
    }
    return System.getenv(TOKEN_TTL_CONFIG_ENV);
  }
}
