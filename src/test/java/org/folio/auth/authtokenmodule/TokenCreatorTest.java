package org.folio.auth.authtokenmodule;

import static org.junit.Assert.assertThrows;

import com.nimbusds.jose.JOSEException;
import io.vertx.core.json.JsonObject;
import java.text.ParseException;
import org.junit.Test;

public class TokenCreatorTest {
  @Test
  public void nullKey() throws JOSEException, ParseException {
    TokenCreator tokenCreator = new TokenCreator((String) null);
    tokenCreator.dryRunAlgorithms();
  }

  @Test
  public void keyTooShort() throws JOSEException, ParseException {
    TokenCreator tokenCreator = new TokenCreator("a");
    tokenCreator.dryRunAlgorithms();
  }

  @Test
  public void keyTooLong() throws JOSEException, ParseException {
    TokenCreator tokenCreator = new TokenCreator("12345678901234567890123456789012345678901234567890");
    tokenCreator.dryRunAlgorithms();
  }

  @Test
  public void key32Umlauts() throws JOSEException, ParseException {
    TokenCreator tokenCreator = new TokenCreator("ääääööööüüüüääääööööüüüüääääöööö");  // 1 umlaut is 2 bytes
    tokenCreator.dryRunAlgorithms();
  }

  @Test
  public void key32Bytes() throws JOSEException, ParseException {
    byte[] bytes = "12345678901234567890123456789012".getBytes();
    TokenCreator tokenCreator = new TokenCreator(bytes);
    tokenCreator.dryRunAlgorithms();
  }

  @Test
  public void expiredToken() throws Exception {
    var tokenCreator = new TokenCreator((String) null);
    var token = tokenCreator.createJWTToken(new JsonObject().put("exp", 5).encode());
    assertThrows("Expired token", BadSignatureException.class, () -> tokenCreator.checkJWTToken(token));
  }
}
