package org.folio.auth.authtokenmodule.tokens.ttl;

public record TokenTTLConfiguration(long accessTokenTtlSeconds, long refreshTokenTtlSeconds) {

}
