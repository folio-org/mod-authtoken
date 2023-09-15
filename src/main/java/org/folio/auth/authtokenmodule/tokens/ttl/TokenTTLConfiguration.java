package org.folio.auth.authtokenmodule.tokens.ttl;

public record TokenTTLConfiguration(long accessTokenTTLSeconds, long refreshTokenTTLSeconds) {

}
