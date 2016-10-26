/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.folio.auth.authtoken_module.impl;

import org.folio.auth.authtoken_module.PermissionsSource;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;

/**
 *
 * @author kurt
 */
public class ModulePermissionsSource implements PermissionsSource {

  private String okapiUrl = null;
  private Vertx vertx;
  private String requestToken;
  private String authApiKey = "";
  private String tenant;
  private final Logger logger = LoggerFactory.getLogger("mod-auth-authtoken-module");
  
  public ModulePermissionsSource(Vertx vertx) {
    //permissionsModuleUrl = url;
    this.vertx = vertx;
  }
  
  public void setOkapiUrl(String url) {
    okapiUrl = url;
    if(!okapiUrl.endsWith("/")) {
      okapiUrl = okapiUrl + "/";
    }
  }
  
  public void setRequestToken(String token) {
    requestToken = token;
  }
  
  public void setAuthApiKey(String key) {
    authApiKey = key;
  }
  
  public void setTenant(String tenant) {
    this.tenant = tenant;
  }
  
  @Override
  public Future<JsonArray> getPermissionsForUser(String username) {
    Future<JsonArray> future = Future.future();
    HttpClientOptions options = new HttpClientOptions();
    options.setConnectTimeout(10);
    options.setIdleTimeout(10);
    HttpClient client = vertx.createHttpClient(options);
    String okapiUrlFinal = "http://localhost:9130/";
    if(okapiUrl != null) {
      okapiUrlFinal = okapiUrl;
    }
    //String requestUrl = okapiUrlFinal + "perms/privileged/users/" + username + "/permissions";
    String requestUrl = okapiUrlFinal + "perms/users/" + username + "/permissions";
    logger.debug("Requesting permissions from URL at " + requestUrl);
    HttpClientRequest req = client.getAbs(requestUrl, res-> {
      if(res.statusCode() == 200) {
        res.bodyHandler(res2 -> {
          JsonArray permissions = new JsonArray(res2.toString());
          future.complete(permissions);
        });
      } else {
        //future.fail("Unable to retrieve permissions");
        res.bodyHandler(res2 -> {
          System.out.println("Unable to retrieve permissions (code " + res.statusCode() + "): " + res2.toString());
        });
        future.complete(new JsonArray());
      }
    });
    req.exceptionHandler(exception -> {
      future.fail(exception);
    });
    req.headers().add("Authorization", "Bearer " + requestToken);
    //req.headers().add("Auth_API_Key", authApiKey);
    req.headers().add("X-Okapi-Tenant", tenant);
    req.end();
    return future;
  }

  
}
