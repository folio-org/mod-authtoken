package org.folio.auth.authtokenmodule;

public class TokenValidationResult {
    public static TokenValidationResult success() {
        return new TokenValidationResult();
    }

    TokenValidationResult() {
        isValid = true;
        httpStatusCode = 202;
    }

    public TokenValidationResult(String errorMessage, int statusCode) {
        isValid = false;
        validationMessage = errorMessage;
        httpStatusCode = statusCode;
    }

    public Boolean isValid;

    public String validationMessage;
    
    public int httpStatusCode;
}
