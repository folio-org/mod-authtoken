package org.folio.auth.authtokenmodule.tokens;

import io.vertx.core.Future;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import java.util.Base64;
import com.nimbusds.jose.JOSEException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.folio.auth.authtokenmodule.BadSignatureException;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.okapi.common.XOkapiHeaders;
import java.text.ParseException;
import java.time.Instant;

import static java.lang.Boolean.TRUE;

/**
 * An abstract class that all token types should extend, with one required method
 * that all must implement to handle their validation logic. This class also exposes
 * a handful of static methods which provide convenient ways of working with tokens,
 * including a method to parse and validate a token in one step.
 */
public abstract class Token {
  public static final String REFRESH_TOKEN = "refreshToken";
  public static final String ACCESS_TOKEN = "accessToken";
  public static final String REFRESH_TOKEN_EXPIRATION = "refreshTokenExpiration";
  public static final String ACCESS_TOKEN_EXPIRATION = "accessTokenExpiration";

  protected static final String UNDEFINED_USER_NAME = "UNDEFINED_USER__";
  protected String source;

  private static final Logger logger = LogManager.getLogger(Token.class);
  private boolean usesDummyPermissionsSource;

  /**
   * Get the claim value for a given claim.
   * @param claim The key of the claim.
   * @return The value of the claim.
   */
  public String getClaim(String claim) {
    return claims.getString(claim);
  }

  /**
   * Gets the claims for this token.
   * @return A JsonObject containing the claims for this token.
   */
  public JsonObject getClaims() {
    return claims;
  }
  protected JsonObject claims;

  public String getTenant() {
    return claims.getString("tenant");
  }

  /**
   * All implementors of Token are required to implement this method. Validation should
   * consist of all operations necessary to determine whether the token can authorize
   * the request.
   * @param context The context for the token validation.
   * @return If the token is valid, implementors should return a Future with a Token object.
   * If the token is not valid, implementors should return a Future with a
   * TokenValidationException.
   * @see TokenValidationException
   */
  protected abstract Future<Token> validateContext(TokenValidationContext context);

  /**
   * Validates the provided token. Validation includes checking everything needed
   * to determine whether the token should be authorized, including the signature and
   * any special validation required by its type.
   * @param context The context for the token validation.
   * @return Future<Token> A Future containing the Token if it has passed validation.
   * The Future may also contain a TokenValidationException if the validation has failed.
   * @see TokenValidationException
   */
  public static Future<Token> validate(TokenValidationContext context) {
    Token token;
    try {
      token = parse(context.getTokenToValidate(), context.getTokenCreator());
    } catch (TokenValidationException e) {
      return Future.failedFuture(e);
    } catch (Exception e) {
      return Future.failedFuture(new TokenValidationException("Unexpected token parse exception", e, 500));
    }

    // Call the validateContext implementation of the underlying token type (AccessToken,
    // RefreshToken, etc.). See those classes for the validation logic specific to each type.
    return token.validateContext(context);
  }

  /**
   * Some tokens require that the dummy permissions source be used. This will return
   * true when that is the case.
   * @return True if the dummy permissions source should be used.
   */
  public boolean shouldUseDummyPermissionsSource() {
    // Dummy tokens are not the only type of tokens that require the use of this
    // so checking the token type alone isn't enough. We also have to check the sub claim.
    if (TRUE.equals(claims.getBoolean("dummy")) ||
      claims.getString("sub").startsWith(Token.UNDEFINED_USER_NAME)) {
      usesDummyPermissionsSource = true;
      return true;
    }

    return false;
  }

  /**
   * Will return true if this this token requires a check that the user is active.
   * @param userId The user id from the request header.
   * @return True if the check should be made.
   */
  public boolean shouldCheckIfUserIsActive(String userId) {
    return !usesDummyPermissionsSource && userId != null && !userId.trim().isEmpty();
  }

  /**
   * Encodes the token as a JWT token.
   * @param tokenCreator The TokenCreator to use to encode the token.
   * @return The encoded token.
   * @throws JOSEException
   * @throws ParseException
   */
  public String encodeAsJWT(TokenCreator tokenCreator) throws JOSEException, ParseException {
    String encodedClaims = claims.encode();
    return tokenCreator.createJWTToken(encodedClaims);
  }

  /**
   * Encodes the token as a JWE token.
   * @param tokenCreator The TokenCreator to use to encode the token.
   * @return The encoded token.
   * @throws JOSEException
   */
  public String encodeAsJWE(TokenCreator tokenCreator) throws JOSEException {
    String encodedClaims = claims.encode();
    return tokenCreator.createJWEToken(encodedClaims);
  }

  /**
   * Gets the claims from the provided JWT.
   * @param jwt A string representing the JWT.
   * @return A JsonObject representing the claims.
   */
  public static JsonObject getClaims(String jwt) {
    String encodedJson = jwt.split("\\.")[1];
    String decodedJson = new String(Base64.getDecoder().decode(encodedJson));
    return new JsonObject(decodedJson);
  }

  /**
   * Returns true if the token is encrypted, otherwise false.
   * @param token A string version of the token to test.
   * @return True if the token is encrypted, otherwise false.
   * @throws TokenValidationException
   */
  public static boolean isEncrypted(String token) throws TokenValidationException {
    // This is based on how JOSEObject parses encrypted tokens. It checks the number of "parts"
    // which are equivalent to the number of "." separators in the token. If there are 5 parts
    // it is considered to be encrypted. If there are not 5 it is rejected from JWE parsing.
    // Our unencrypted tokens have 3 parts (and 2 separators).
    int parts = token.split("\\.").length;
    if (parts == 5) {
      return true;
    }

    if (parts == 3) {
      return false;
    }

    throw new TokenValidationException("Unexpected token part count", 401);
  }

  public static Token parse(String sourceToken, TokenCreator tokenCreator) throws TokenValidationException {
    JsonObject claims;
    final String invalidTokenMsg = "Invalid token";

    try {
      if (isEncrypted(sourceToken)) {
        String tokenContent = tokenCreator.decodeJWEToken(sourceToken);
        claims = new JsonObject(tokenContent);
      } else {
        tokenCreator.checkJWTToken(sourceToken);
        claims = getClaims(sourceToken);
      }
    } catch (ParseException p) {
      throw new TokenValidationException(invalidTokenMsg, p, 401);
    } catch (JOSEException j) {
      throw new TokenValidationException(invalidTokenMsg, j, 401);
    } catch (BadSignatureException b) {
      final String msg = "Invalid token signature. "
          + "This might have been caused by a mod-authtoken restart if jwt.signing.key is not set, "
          + "or by running multiple mod-authtoken instances without setting the same jwt.signing.key.";
      throw new TokenValidationException(msg, b, 401);
    }

    String tokenType = claims.getString("type");
    if (tokenType == null)
      throw new TokenValidationException("Token has no type", 400);

    switch (tokenType) {
      case LegacyAccessToken.TYPE:
        return new LegacyAccessToken(sourceToken, claims);
      case AccessToken.TYPE:
        return new AccessToken(sourceToken, claims);
      case RefreshToken.TYPE:
        return new RefreshToken(sourceToken, claims);
      case ApiToken.TYPE:
        return new ApiToken(sourceToken, claims);
      case DummyToken.TYPE:
        return new DummyToken(sourceToken, claims);
      case ModuleToken.TYPE:
        return new ModuleToken(sourceToken, claims);
      default:
        throw new TokenValidationException("Unable to parse token", 400);
    }
  }


  /**
   * Validate all the things that tokens have in common.
   * @param request The http request context where the token is being provided.
   * @throws TokenValidationException Throws this when any validation step fails, but may throw
   * other exceptions as well.
   */
  protected void validateCommon(HttpServerRequest request) throws TokenValidationException {
    try {
      // Check that the token has a source.
      if (source == null) {
        throw new TokenValidationException("Token has no source defined", 500);
      }

      // Check that the claims have been created.
      if (claims == null) {
        throw new TokenValidationException("Token has no claims", 500);
      }

      // Check some claims that all tokens must have.
      String[] requiredClaims = new String[] { "sub", "tenant", "type" };
      for (String c : requiredClaims) {
        if (!claims.containsKey(c)) {
          throw new TokenValidationException(String.format("Token is missing %s claim", c), 500);
        }
      }

      if (request == null) {
        return;
      }

      // Check that some items in the headers match what are in the token.
      String headerTenant = request.headers().get(XOkapiHeaders.TENANT);
      if (!claims.getString("tenant").equals(headerTenant)) {
        throw new TokenValidationException("Tenant mismatch: tenant in header does not equal tenant in token", 403);
      }
      String headerUserId = request.headers().get(XOkapiHeaders.USER_ID);
      String claimsUserId = claims.getString("user_id");
      if (headerUserId != null && claimsUserId != null && !claimsUserId.equals(headerUserId)) {
        throw new TokenValidationException("User id in header does not equal user id in token", 403);
      }
    } catch (TokenValidationException e) {
      throw e;
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
      throw new TokenValidationException("Unexpected token validation exception", e, 500);
    }
  }

  protected boolean tokenIsExpired() {
    Long nowTime = Instant.now().getEpochSecond();
    Long expiration = claims.getLong("exp");
    return nowTime > expiration;
  }
}
