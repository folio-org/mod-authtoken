package org.folio.auth.authtokenmodule.tokens.expiration;

public record TokenExpirationConfiguration(long accessTokenExpirationSeconds, long refreshTokenExpirationSeconds) {

}
