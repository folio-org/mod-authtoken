package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;

import org.folio.auth.authtokenmodule.BadSignatureException;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.okapi.common.XOkapiHeaders;

import java.text.ParseException;

public abstract class Token {
  private static final String CALLING_MODULE_HEADER = "X-Okapi-Calling-Module";
  protected static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";
  protected String source;
  private boolean usesDummyPermissionsSource;

  /**
   * Gets the claims for this token.
   * @return A JsonObject containing the claims for this token.
   */
  public JsonObject getClaims() {
    return claims;
  }
  protected JsonObject claims;

  /** 
   * Validates the provided JWT token. Validation includes checking everything needed
   * to determine whether the token should be authorized, including the signature and
   * any special validation required by its type.
   * @param jwt The JWT token to validate.
   * @param request The request in the http context where the token is being provided.
   * @return Future<Token> A Future containing the Token if it has passed validation.
   * The Future may also contain a TokenValidationException if the validation has failed.
   * @see TokenValidationException.
   */
  public static Future<Token> validate(String jwt, HttpServerRequest request) {
    Token token = null;
    try {
      token = parse(jwt);
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    } catch (Exception e) {
      return Future.failedFuture(new TokenValidationException("Unexpected token parse exception", e, 500));
    }

    return token.validate(request);
  }

  /**
   * Some tokens require that the dummy permissions source be used. This will return
   * true when that is the case.
   * @return True if the dummy permissions source should be used.
   */
  public boolean shouldUseDummyPermissionsSource() {
    // Dummy tokens are not the only type of tokens that require the use of this
    // so checking the token type alone isn't enough. We also have to check the sub claim.
    if ((claims.getBoolean("dummy") != null &&
         claims.getBoolean("dummy"))
      || claims.getString("sub").startsWith(Token.UNDEFINED_USER_NAME)) {
        usesDummyPermissionsSource = true;
        return true;
      }

    return false;
  }

  /**
   * Will return true if this this token requires a check that the user is active.
   * @param requestHeaders The headers in the http context where the token is being provided.
   * @return True if the check should be made.
   */
  public boolean shouldCheckIfUserIsActive(MultiMap requestHeaders) {
    var userId = requestHeaders.get(XOkapiHeaders.USER_ID);
    return !usesDummyPermissionsSource && userId != null && !userId.trim().isEmpty();
  }

  /**
   * Will add the calling module if the request headers require it.
   * @param requestHeaders The headers in the http context where the token is being provided.
   */
  public void tryAddCallingModule(MultiMap requestHeaders) {
    if (requestHeaders.contains(CALLING_MODULE_HEADER)) {
      claims.put("calling_module", requestHeaders.get(CALLING_MODULE_HEADER));
    }
  }

  public String encodeAsJWT() throws JOSEException, ParseException {
    String key = System.getProperty("jwt.signing.key");
    String encodedClaims = claims.encode();
    return new TokenCreator(key).createJWTToken(encodedClaims);
  }

  public String encodeAsJWE() throws JOSEException, ParseException {
    String key = System.getProperty("jwt.signing.key");
    String encodedClaims = claims.encode();
    return new TokenCreator(key).createJWEToken(encodedClaims);
  }

  public static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  protected abstract Future<Token> validate(HttpServerRequest request);

  protected void validateCommon(HttpServerRequest request) throws TokenValidationException {
    try {
      // Check that the token has a source.
      if (source == null)
        throw new TokenValidationException("Token has no source defined", 500);

      // Check that the token is parsable and signed.
      final String invalidTokenMsg = "Invalid token"; // Be intentionally vague.
      try {
        // TODO Is there a penalty here? Should the TokenCreator be passed in as an arg?
        var tc = new TokenCreator(System.getProperty("jwt.signing.key"));
        tc.checkJWTToken(source);
      } catch (ParseException p) {
        throw new TokenValidationException(invalidTokenMsg, p, 401);
      } catch (JOSEException j) {
        throw new TokenValidationException(invalidTokenMsg, j, 401);
      } catch (BadSignatureException b) {
        throw new TokenValidationException(invalidTokenMsg, b, 401);
      }

      // Check that the claims have been created.
      if (claims == null)
        throw new TokenValidationException("Token has no claims", 500);

      // Check some claims that all tokens must have.
      String[] requiredClaims = new String[] { "sub", "tenant", "type" };
      for (String c : requiredClaims) {
        if (!claims.containsKey(c)) {
          throw new TokenValidationException(String.format("Token is missing %s claim", c), 500);
        }
      }

      if (request == null)
        return;

      // Check that some items in the headers match what are in the token.
      String headerTenant = request.headers().get(XOkapiHeaders.TENANT);
      if (!claims.getString("tenant").equals(headerTenant))
        throw new TokenValidationException("Tenant in header does not equal tenant in token", 403);

      String headerUserId = request.headers().get(XOkapiHeaders.USER_ID);
      if (headerUserId != null && !claims.getString("user_id").equals(headerUserId))
        throw new TokenValidationException("User id in header does not equal userid in token", 403);

    } catch (TokenValidationException e) {
      throw e;
    } catch (Exception e) {
      throw new TokenValidationException("Unexpected token validation exception", e, 500);
    }
  }

  private static Token parse(String jwtSource) throws TokenValidationException {
    Token token = null;
    JsonObject claims = null;
    try {
      claims = getClaims(jwtSource);
    } catch (Exception e) {
      throw new TokenValidationException("Unable to get token claims", e, 401);
    }

    String tokenType = claims.getString("type");
    if (tokenType == null)
      throw new TokenValidationException("Token has no type", 400);

    // TODO Pass token claims in here so that we don't have to get them twice.
    // This is now fine since these constructors are protected.
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
      // TODO Why is this working without tokens of type Request?
      default:
        break;
    }

    if (token == null)
      throw new TokenValidationException("Unsupported token type", 400);
    return token;
  }

}
