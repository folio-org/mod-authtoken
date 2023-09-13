package org.folio.auth.authtokenmodule.tokens.ttl;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.util.Arrays;
import java.util.HashMap;

public class TokenTTL {
  public static final String TOKEN_TTL_CONFIG = "token.ttl.config";
  public static final String TOKEN_TTL_CONFIG_ENV = "TOKEN_TTL_CONFIG";

  public static final String MISCONFIGURED_TENANT = "Tenant expected in token TTL configuration";

  public static final String MISCONFIGURED_NO_DEFAULT = "No default configuration provided for token TTL configuration";

  public static final String MISCONFIGURED_INCORRECT_VALUE = "Token TTL configuration has an incorrect value";

  public static final String MISCONFIGURED_MISSING_SEPARATOR = "Token TTL configuration is missing at least one separator";

  public static final String MISCONFIGURED_INVALID_ENTRY = "Token TTL configuration has an invalid entry";

  public static final String MISCONFIGURED_UNKNOWN_KEY = "Token TTL configuration has an unknown key";

  private static TokenTTL instance;

  public static TokenTTL getInstance() {
    if (instance == null) {
      instance = new TokenTTL();
    }
    return instance;
  }

  public static void resetInstance() {
    instance = null;
  }

  private TokenTTL() {
    tenantTokenConfiguration = new HashMap<>();

    String tokenTtlConfiguration = getTtlConfig();

    if (tokenTtlConfiguration == null) {
      defaultTtlConfiguration = new TokenTTLConfiguration(AccessToken.DEFAULT_EXPIRATION_SECONDS,
        RefreshToken.DEFALUT_EXPIRATION_SECONDS);
    } else {
      parseTtlConfig(tokenTtlConfiguration);
    }
  }

  public long getAccessTokenTll(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.accessTokenTtlSeconds();
    }
    return defaultTtlConfiguration.accessTokenTtlSeconds();
  }

  public long getRefreshTokenTtl(String tenant) {
    var tenantConfiguration = tenantTokenConfiguration.get(tenant);
    if (tenantConfiguration != null) {
      return tenantConfiguration.refreshTokenTtlSeconds();
    }
    return defaultTtlConfiguration.refreshTokenTtlSeconds();
  }

  private TokenTTLConfiguration defaultTtlConfiguration;

  private final HashMap<String, TokenTTLConfiguration> tenantTokenConfiguration;

  private void parseTtlConfig(String tokenTtlConfig) {
    if (!tokenTtlConfig.contains(":") || !tokenTtlConfig.contains(","))
      throw new TokenTTLConfigurationException(MISCONFIGURED_MISSING_SEPARATOR);

    var configEntries = tokenTtlConfig.replace(" ", "").split(";");
    for (String configEntry : configEntries) {
      String tenantId = null;
      long accessTokenTtl = 0;
      long refreshTokenTtl = 0;

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
          case "refreshToken" -> refreshTokenTtl = Long.parseLong(value);
          case "accessToken" -> accessTokenTtl = Long.parseLong(value);
          default -> throw new TokenTTLConfigurationException(MISCONFIGURED_UNKNOWN_KEY);
        }
      }

      if (accessTokenTtl <= 0 || refreshTokenTtl <= 0)
        throw new TokenTTLConfigurationException(MISCONFIGURED_INCORRECT_VALUE);

      if (keyValuePairs.length == 3 && tenantId == null)
        throw new TokenTTLConfigurationException(MISCONFIGURED_TENANT);

      if (tenantId != null) {
        tenantTokenConfiguration.put(tenantId, new TokenTTLConfiguration(accessTokenTtl, refreshTokenTtl));
      } else {
        defaultTtlConfiguration = new TokenTTLConfiguration(accessTokenTtl, refreshTokenTtl);
      }
    }

    if (defaultTtlConfiguration == null)
      throw new TokenTTLConfigurationException(MISCONFIGURED_NO_DEFAULT);
  }

  private String getTtlConfig() {
    var prop = System.getProperty(TOKEN_TTL_CONFIG);
    if (prop != null) {
      return prop;
    }
    return System.getenv(TOKEN_TTL_CONFIG_ENV);
  }
}
