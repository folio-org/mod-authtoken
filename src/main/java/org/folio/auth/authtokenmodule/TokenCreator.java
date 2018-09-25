package org.folio.auth.authtokenmodule;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import org.folio.auth.authtokenmodule.BadSignatureException;

public class TokenCreator {
  private byte[] sharedKey;
  private MACSigner macSigner;
  private MACVerifier macVerifier;
  private DirectEncrypter encrypter;
  private DirectDecrypter decrypter;
  JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
  JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);

  public TokenCreator(String key) throws KeyLengthException, JOSEException {
   if(key != null) {
     //pad to minimum length
     if(key.length() < 32) {
       key = String.format("%-32s", key);
     }
     if(key.length() > 32) {
       key = key.substring(0, 32);
     }
     init(key.getBytes());
   } else {
     byte[] tempKey = new byte[64];
     new SecureRandom().nextBytes(tempKey);
     init(tempKey);
   }
  }

  public TokenCreator(byte[] byteArray) throws KeyLengthException, JOSEException {
    init(byteArray);
  }

  private void init(byte[] setKey) throws KeyLengthException, JOSEException {
    sharedKey = setKey;
    macSigner = new MACSigner(sharedKey);
    macVerifier = new MACVerifier(sharedKey);
    encrypter = new DirectEncrypter(sharedKey);
    decrypter = new DirectDecrypter(sharedKey);
  }

  /**
   * Set the algorithm for {@link #createJWEToken(String)}.
   * @param jweHeader the new algorithm
   */
  public void setJweHeader(JWEHeader jweHeader) {
    this.jweHeader = jweHeader;
  }

  /*
   * payload should be an encoded JSON object
   * I know 'JWTToken' is redundant, but I don't care...muahahahaha
   */
  public String createJWTToken(String payload) throws JOSEException, ParseException {
    JWTClaimsSet claims = JWTClaimsSet.parse(payload);
    SignedJWT jwt = new SignedJWT(jwsHeader, claims);
    jwt.sign(macSigner);
    return jwt.serialize();
  }

  public void checkJWTToken(String token) throws JOSEException, ParseException,
      BadSignatureException {
    SignedJWT jwt = SignedJWT.parse(token);
    if(!jwt.verify(macVerifier)) {
      String message = String.format("Could not verify token %s", token);
      throw(new BadSignatureException(message));
    };
  }

  public String createJWEToken(String payloadString) throws JOSEException {
    Payload payload = new Payload(payloadString);
    JWEObject jwe = new JWEObject(jweHeader, payload);
    jwe.encrypt(encrypter);
    return jwe.serialize();
  }

  public String decodeJWEToken(String token) throws JOSEException, ParseException {
    JWEObject jwe = JWEObject.parse(token);
    jwe.decrypt(decrypter);
    return jwe.getPayload().toString();
  }

  /**
   * Create a dummy JWT token and a dummy JWE token to dry run the configured algorithms.
   * @throws JOSEException  if an algorithm is not available
   * @throws ParseException  on JWT parse error
   */
  public void dryRunAlgorithms() throws JOSEException, ParseException {
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .subject("One Thousand and One Nights")
        .issuer("https://example.com")
        .expirationTime(new Date())
        .build();
    createJWTToken(claimsSet.toString());
    createJWEToken("Ali Baba and the Forty Thieves");
  }
}
