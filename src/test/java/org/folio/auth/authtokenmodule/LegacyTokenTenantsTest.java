package org.folio.auth.authtokenmodule;

import org.folio.auth.authtokenmodule.tokens.legacy.LegacyTokenTenants;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class LegacyTokenTenantsTest {

  @BeforeEach
  @AfterEach
  public void clearSystemProperty() {
    System.clearProperty(LegacyTokenTenants.LEGACY_TOKEN_TENANTS);
  }

  @ParameterizedTest
  @ValueSource(strings = { "tenant1", "tenant2, tenant1", "tenant2,tenant1" }) // Only configured tenants are allowed.
  void legacyTokenTenantsConfigPositive(String tenants) {
    System.setProperty(LegacyTokenTenants.LEGACY_TOKEN_TENANTS, tenants);

    var legacyTenants = new LegacyTokenTenants();
    assertThat(legacyTenants.isLegacyTokenTenant("tenant1"), is(true));
    assertThat(legacyTenants.isLegacyTokenTenant("tenant3"), is(false));
  }

  @ParameterizedTest
  @ValueSource(strings = { "*", " *  " }) // All tenants are allowed.
  void legacyTokenTenantsConfigAllTenants(String tenants) {
    System.setProperty(LegacyTokenTenants.LEGACY_TOKEN_TENANTS, tenants);

    var legacyTenants = new LegacyTokenTenants();
    assertThat(legacyTenants.isLegacyTokenTenant("tenant1"), is(true));
  }

  @ParameterizedTest
  @ValueSource(strings = { "", "   " }) // No tenants are allowed.
  void legacyTokenTenantsConfigNoTenants(String tenants) {
    System.setProperty(LegacyTokenTenants.LEGACY_TOKEN_TENANTS, tenants);

    var legacyTenants = new LegacyTokenTenants();
    assertThat(legacyTenants.isLegacyTokenTenant("tenant1"), is(false));
  }

  @Test
  void legacyTokenTenantsConfigNoConfig() { // No config, so all are allowed.
    var legacyTenants = new LegacyTokenTenants();
    assertThat(legacyTenants.isLegacyTokenTenant("tenant1"), is(true));
  }
}
