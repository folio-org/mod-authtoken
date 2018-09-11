package org.folio.auth.authtokenmodule;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.text.ParseException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.folio.auth.authtokenmodule.BadSignatureException;



public class TokenCreator {
  private static final EncryptionMethod encryptionMethod = EncryptionMethod.A256CBC_HS512;
  private byte[] sharedKey;
  private MACSigner macSigner;
  private MACVerifier macVerifier;
  private DirectEncrypter encrypter;
  private DirectDecrypter decrypter;
  

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

  /*
   * payload should be an encoded JSON object
   * I know 'JWTToken' is redundant, but I don't care...muahahahaha
   */
  public String createJWTToken(String payload) throws JOSEException, ParseException {
    JWTClaimsSet claims = JWTClaimsSet.parse(payload);
    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
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
    JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
    JWEObject jwe = new JWEObject(header, payload);
    jwe.encrypt(encrypter);
    return jwe.serialize();
  }
  
  public String decodeJWEToken(String token) throws JOSEException, ParseException {
    JWEObject jwe = JWEObject.parse(token);
    jwe.decrypt(decrypter);
    return jwe.getPayload().toString();
  }
}
