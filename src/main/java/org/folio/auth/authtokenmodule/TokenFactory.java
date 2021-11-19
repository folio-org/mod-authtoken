package org.folio.auth.authtokenmodule;

public class TokenFactory {

  // TODO Create a TokenArgs and TokenArgsBuilder class that can be the argument
  // here and also be the argument for every token's constructor.
  // This is needed because each token requires different types of arguments
  // with the only common one being tenant. But it shouln't be necessary for this
  // mess to be exposed.

  // Although maybe it is completely fine to let clients use the token constructors
  // directly, because they need to know that anyway.
  public static Token createNewToken(String tokenType) {
    Token token = null;

    switch (tokenType) {
    case TokenType.REFRESH:
      token = new RefreshToken();
      break;

    // TODO Add other types.

    default:
      break;
    }

    return token;
  }

  public static Token parseToken(String jwt) {
    Token token = null;

    String tokenType = Token.getTokenType(jwt);

    switch (tokenType) {
    case TokenType.REFRESH:
      token = new RefreshToken(jwt);
      break;

    // TODO Add other types.

    default:
      break;
    }

    return token;
  }

}