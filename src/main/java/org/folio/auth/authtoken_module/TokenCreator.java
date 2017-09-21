package org.folio.auth.authtoken_module;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;


public class TokenCreator {
  private Key JWTSigningKey;
  private JwtParser parser;
  private static final SignatureAlgorithm JWTAlgorithm = SignatureAlgorithm.HS512;

  public TokenCreator(String key) {
    if(key != null) {
      JWTSigningKey = new SecretKeySpec(key.getBytes(), JWTAlgorithm.getJcaName());
    } else {
      JWTSigningKey = MacProvider.generateKey(JWTAlgorithm);
    }
    parser = Jwts.parser().setSigningKey(JWTSigningKey);
  }

  /*
   * payload should be an encoded JSON object
   */
  public String createToken(String payload) {
    String token = Jwts.builder()
      .signWith(JWTAlgorithm, JWTSigningKey)
      .setPayload(payload)
      .compact();
    return token;
  }

  public void checkToken(String token) throws SignatureException, MalformedJwtException, UnsupportedJwtException {
    parser.parseClaimsJws(token);
  }
}
