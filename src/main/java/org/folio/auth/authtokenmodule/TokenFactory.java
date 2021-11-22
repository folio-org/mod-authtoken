package org.folio.auth.authtokenmodule;

import io.vertx.core.json.JsonObject;

public class TokenFactory {

  public static Token parseTokenType(String jwtSource) {
    Token token = null;

    JsonObject claims = Token.getClaims(jwtSource);

    switch (claims.getString("type")) {
    case TokenType.REFRESH:
      token = new RefreshToken(jwtSource);
      break;
    case TokenType.ACCESS:
      token = new AccessToken(jwtSource);
      break;


    // TODO Add other types.

    default:
      break;
    }

    return token;
  }

}