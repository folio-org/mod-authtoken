package org.folio.auth.authtokenmodule.tokens.ttl;

import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;

import java.util.HashMap;

public class TokenTTL {
  public static final String TOKEN_TTL_CONFIG = "token.ttl.config";
  public static final String TOKEN_TTL_CONFIG_ENV = "TOKEN_TTL_CONFIG";

  public static final String MISCONFIGURED_TENANT = "Tenant expected in token TTL configuration";

  public static final String MISCONFIGURED_NO_DEFAULT = "No default configuration provided for token TTL configuration";

  public static final String MISCONFIGURED_AT = "No valid accessToken TTL provided in token TTL configuration";

  public static final String MISCONFIGURED_RT = "No valid refreshToken TTL provided in token TTL configuration";

  public static final String MISCONFIGURED_MISSING_SEPARATOR = "Token TTL configuration is missing at least one separator";

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

    String[] config = tokenTtlConfig.replace(" ", "").split(";");
    for (String c : config) {
      String[] pairs = c.split(",");

      String tenantId = null;
      long accessTokenTtl = 0;
      long refreshTokenTtl = 0;

      for (String p : pairs) {
        String[] keyValue = p.split(":");

        if (keyValue[0].equals("tenantId")) {
          tenantId = keyValue[1];
        }

        if (keyValue[0].equals("refreshToken")) {
          refreshTokenTtl = Long.parseLong(keyValue[1]);
        }

        if (keyValue[0].equals("accessToken")) {
          accessTokenTtl = Long.parseLong(keyValue[1]);
        }
      }

      if (accessTokenTtl <= 0)
        throw new TokenTTLConfigurationException(MISCONFIGURED_AT);

      if (refreshTokenTtl <= 0)
        throw new TokenTTLConfigurationException(MISCONFIGURED_RT);

      if (pairs.length == 3 && tenantId == null)
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
