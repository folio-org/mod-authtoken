package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.JsonObject;

public class TokenFactory {

  public static Token parseTokenType(String jwtSource) throws TokenValidationException {
    Token token = null;

    JsonObject claims = Token.getClaims(jwtSource);

    switch (claims.getString("type")) {
    case TokenType.ACCESS:
      token = new AccessToken(jwtSource);
      break;
    case TokenType.REFRESH:
      token = new RefreshToken(jwtSource);
      break;
    case TokenType.API:
      token = new ApiToken(jwtSource);
      break;
    case TokenType.DUMMY:
      token = new DummyToken(jwtSource);
      break;
    case TokenType.MODULE:
      token = new ModuleToken(jwtSource);
      break;
    default:
      break;
    }

    if (token == null)
      throw new TokenValidationException("Unsupported or non existent token type");
    return token;
  }

}