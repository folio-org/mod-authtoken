package org.folio.auth.authtokenmodule.tokens.legacy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class LegacyTokenTenants {
  public static final String LEGACY_TOKEN_TENANTS = "legacy.token.tenants";
  public static final String LEGACY_TOKEN_TENANTS_ENV = "LEGACY_TOKEN_TENANTS";
  public static final String ALL_TENANTS_LEGACY_CONFIG = "*";

  private final List<String> tenants;
  private boolean allTenantsLegacy;

  public boolean isLegacyTokenTenant(String tenantId) {
    if (this.allTenantsLegacy) {
      return true;
    }
    return tenants.contains(tenantId);
  }

  public LegacyTokenTenants() {
    this.tenants = parseTenants();
  }

  private List<String> parseTenants() {
    var prop = getTenantsFromEnvOrSystemProperty();
    if (prop == null || ALL_TENANTS_LEGACY_CONFIG.equals(prop.trim())) {
      this.allTenantsLegacy = true;
      return Collections.emptyList();
    }

    if (prop.trim().isEmpty()) {
      return Collections.emptyList();
    }

    return Arrays.asList(prop.replace(" ", "").split(","));
  }

  private String getTenantsFromEnvOrSystemProperty() {
    var prop = System.getProperty(LEGACY_TOKEN_TENANTS);
    if (prop != null) {
      return prop;
    }
    return System.getenv(LEGACY_TOKEN_TENANTS_ENV);
  }
}
