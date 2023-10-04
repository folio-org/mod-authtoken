package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.legacy.EnhancedSecurityTenantException;
import org.folio.auth.authtokenmodule.tokens.legacy.EnhancedSecurityTenants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class EnhancedSecurityTenantsTest {

  @BeforeEach
  @AfterEach
  public void clearSystemProperty() {
    System.clearProperty(EnhancedSecurityTenants.ENHANCED_SECURITY_TENANTS);
  }

  @ParameterizedTest
  @ValueSource(strings = { "tenant1", "tenant2, tenant1" })
  void enhancedSecurityTenantsConfigPositive(String tenants) {
    System.setProperty(EnhancedSecurityTenants.ENHANCED_SECURITY_TENANTS, tenants);

    var esTenants = new EnhancedSecurityTenants();
    assertThat(esTenants.isEnhancedSecurityTenant("tenant1"), is(true));
  }


  @ParameterizedTest
  @ValueSource(strings = { "", "   " })
  void enhancedSecurityTenantsConfigNegative(String tenants) {
    System.setProperty(EnhancedSecurityTenants.ENHANCED_SECURITY_TENANTS, tenants);

    Throwable t = Assertions.assertThrows(EnhancedSecurityTenantException.class, EnhancedSecurityTenants::new);
    assertThat(t.getMessage(), is(EnhancedSecurityTenants.ENHANCED_SECURITY_TENANTS_EMPTY));
  }
}
