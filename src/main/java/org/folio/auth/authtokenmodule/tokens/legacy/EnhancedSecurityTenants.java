package org.folio.auth.authtokenmodule.tokens.legacy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class EnhancedSecurityTenants {
  public static final String ENHANCED_SECURITY_TENANTS = "enhanced.security.tenants";

  public static final String ENHANCED_SECURITY_TENANTS_ENV = "ENHANCED_SECURITY_TENANTS";

  public boolean isEnhancedSecurityTenant(String tenantId) {
    return tenants.contains(tenantId);
  }
  private final List<String> tenants;
  public EnhancedSecurityTenants() {
    this.tenants = parseTenants();
  }

  private List<String> parseTenants() {
    var prop = getTenantsFromEnvOrSystemProperty();
    if (prop == null) {
      return Collections.emptyList();
    }
    return Arrays.asList(prop.replace(" ", "").split(","));
  }

  private String getTenantsFromEnvOrSystemProperty() {
    var prop = System.getProperty(ENHANCED_SECURITY_TENANTS);
    if (prop != null) {
      return prop;
    }
    return System.getenv(ENHANCED_SECURITY_TENANTS_ENV);
  }
}
