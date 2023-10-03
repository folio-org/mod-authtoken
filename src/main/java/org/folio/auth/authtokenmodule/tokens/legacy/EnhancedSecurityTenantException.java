package org.folio.auth.authtokenmodule.tokens.legacy;

public class EnhancedSecurityTenantException extends RuntimeException {
  public EnhancedSecurityTenantException() {
    super("Tenant is enhanced security tenant as specified in this modules environment or system property. " +
      "Cannot issue non-expiring legacy token.");
  }
}
