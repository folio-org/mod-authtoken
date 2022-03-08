package org.folio.auth.authtokenmodule.apis;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.openapi.RouterBuilder;
import io.vertx.core.http.HttpMethod;

import org.folio.auth.authtokenmodule.AuthtokenException;
import org.folio.auth.authtokenmodule.TokenCreator;
import org.folio.auth.authtokenmodule.tokens.AccessToken;
import org.folio.auth.authtokenmodule.tokens.RefreshToken;
import org.folio.auth.authtokenmodule.tokens.Token;
import org.folio.auth.authtokenmodule.tokens.TokenValidationContext;
import org.folio.okapi.common.XOkapiHeaders;

import org.apache.logging.log4j.LogManager;

import org.folio.tlib.RouterCreator;

public class RefreshTokenApi extends TokenApi implements RouterCreator {
  private TokenCreator tokenCreator;

  public RefreshTokenApi(Vertx vertx, TokenCreator tc) {
    logger = LogManager.getLogger(RefreshTokenApi.class);
    tokenCreator = tc;
  }

  @Override
  public Future<Router> createRouter(Vertx vertx) {
    return RouterBuilder.create(vertx, "openapi/refresh-token-1.0.yaml")
        .map(routerBuilder -> {
          routerBuilder
              .operation("refresh")
              .handler(this::handleRefresh);
          routerBuilder
              .operation("refreshtoken")
              .handler(this::handleSignRefreshToken);
          return routerBuilder.createRouter();
        });
  }

  /*
   * In order to get a new access token, the client should issue a POST request
   * to the refresh endpoint, with the content being a JSON object with the
   * following
   * structure:
   * {
   * "refreshToken" : ""
   * }. The module will then check the refresh token for validity, generate a new
   * access token
   * and return it in the body of the response as a JSON object:
   * {
   * "token" : ""
   * }
   */
  private void handleRefresh(RoutingContext ctx) {
    try {
      logger.debug("Token refresh request from {}", ctx.request().absoluteURI());

      if (ctx.request().method() != HttpMethod.POST) {
        endText(ctx, 400, "Invalid method for this endpoint");
        return;
      }

      String content = ctx.getBodyAsString();
      JsonObject requestJson;

      try {
        requestJson = parseJsonObject(content, new String[] { "refreshToken" });
      } catch (Exception e) {
        endText(ctx, 400, "Unable to parse content of refresh token request: ", e);
        return;
      }

      String encryptedJWE = requestJson.getString("refreshToken");
      var context = new TokenValidationContext(ctx.request(), tokenCreator, encryptedJWE);
      Future<Token> tokenValidationResult = Token.validate(context);

      tokenValidationResult.onFailure(h -> {
        String msg = "Invalid token in handleRefresh";
        String unexpectedExceptionMsg = "Unexpected token exception in handleRefresh";
        handleTokenValidationFailure(h, ctx, msg, unexpectedExceptionMsg);
      });

      tokenValidationResult.onSuccess(token -> {
        String username = token.getClaims().getString("sub");
        String userId = token.getClaims().getString("user_id");
        String tenant = token.getClaims().getString("tenant");

        try {
          // TODO To do RTR we need to return both a new AT and a new RT here.
          String at = new AccessToken(tenant, username, userId).encodeAsJWT(tokenCreator);
          JsonObject responseObject = new JsonObject().put("token", at);
          endJson(ctx, 201, responseObject.encode());
        } catch (Exception e) {
          endText(ctx, 500, String.format("Unanticipated exception creating access token: %s", e.getMessage()));
        }
      });
    } catch (Exception e) {
      endText(ctx, 500, String.format("Unanticipated exception when handling refresh: %s", e.getMessage()));
    }
  }

  /*
   * POST a request with a json payload, containing the following:
   * {
   * "userId" : "",
   * "sub" : ""
   * }
   */
  private void handleSignRefreshToken(RoutingContext ctx) {
    try {
      if (ctx.request().method() != HttpMethod.POST) {
        String message = String.format("Invalid method '%s' for this endpoint '%s'",
            ctx.request().method().toString(),
            ctx.request().absoluteURI());
        endText(ctx, 400, message);
        return;
      }
      String tenant = ctx.request().headers().get(XOkapiHeaders.TENANT);
      String address = ctx.request().remoteAddress().host();
      String content = ctx.getBodyAsString();
      JsonObject requestJson;
      try {
        requestJson = parseJsonObject(content, new String[] { "userId", "sub" });
      } catch (Exception e) {
        endText(ctx, 400, "Unable to parse content: ", e);
        return;
      }
      String userId = requestJson.getString("userId");
      String sub = requestJson.getString("sub");
      String refreshToken = new RefreshToken(tenant, sub, userId, address).encodeAsJWE(tokenCreator);
      JsonObject responseJson = new JsonObject().put("refreshToken", refreshToken);
      endJson(ctx, 201, responseJson.encode());
    } catch (Exception e) {
      endText(ctx, 500, e);
    }
  }

  // TODO This shouldn't be needed now with openapi
  private JsonObject parseJsonObject(String encoded, String[] requiredMembers)
      throws AuthtokenException {
    JsonObject json;
    try {
      json = new JsonObject(encoded);
    } catch (Exception e) {
      throw new AuthtokenException(String.format("Unable to parse JSON %s: %s", encoded,
          e.getLocalizedMessage()));
    }
    for (String s : requiredMembers) {
      if (!json.containsKey(s)) {
        throw new AuthtokenException(String.format("Missing required member: '%s'", s));
      }
      if (json.getValue(s) == null) {
        throw new AuthtokenException(String.format("Null value for required member: '%s'", s));
      }
    }
    return json;
  }
}
