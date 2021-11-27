package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;

public class TokenFactory {

  public static Token parseJWTToken(String jwtSource) throws TokenValidationException {
    Token token = null;
    JsonObject claims = null;
    try {
      claims = Token.getClaims(jwtSource);
    } catch (Exception e) {
      throw new TokenValidationException("Unable to get token claims", e, 401);
    }

    String tokenType = claims.getString("type");
    if (tokenType ==  null)
      throw new TokenValidationException("Token has no type", 400);

    switch (tokenType) {
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
      throw new TokenValidationException("Unsupported token type", 400);
    return token;
  }

}