package com.auth0.spring.security.api.hmac;

import com.auth0.Auth0Exception;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import com.auth0.spring.security.api.Auth0TokenHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

public class Auth0HMACTokenHelper extends Auth0TokenHelper<Object> {

    @SuppressWarnings("unchecked")
    @Override
    public String generateToken(final Object object, String issuer, String audience, final long expiration) {
        Assert.isInstanceOf(java.util.Map.class, object, "Claims object is not a java.util.Map");
        try {
            final JWTSigner jwtSigner = new JWTSigner(Base64.decodeBase64(getClientSecret()));
            final HashMap<String, Object> claims = new HashMap<>();
            claims.putAll((Map) object);
            claims.put("exp", expiration);
            claims.put("iss", issuer);
            claims.put("aud", audience);
            return jwtSigner.sign(claims);
        } catch (Exception e) {
            throw new Auth0Exception("Token generation error", e);
        }
    }

    @Override
    public Object decodeToken(final String token) {
        final JWTVerifier jwtVerifier = new JWTVerifier(Base64.decodeBase64(getClientSecret()), getClientId());
        try {
            final Map<String, Object> verify = jwtVerifier.verify(token);
            final String payload = (String) verify.get("$");
            @SuppressWarnings("unchecked") final Map<String, String> map = new ObjectMapper().readValue(payload, Map.class);
            return map;
        } catch (InvalidKeyException e) {
            throw new Auth0Exception("InvalidKeyException during decodeToken operation", e);
        } catch (NoSuchAlgorithmException e) {
            throw new Auth0Exception("NoSuchAlgorithmException during decodeToken operation", e);
        } catch (IllegalStateException e) {
            throw new Auth0Exception("IllegalStateException during decodeToken operation", e);
        } catch (SignatureException e) {
            throw new Auth0Exception("SignatureException during decodeToken operation", e);
        } catch (IOException e) {
            throw new Auth0Exception("IOException during decodeToken operation", e);
        } catch (JWTVerifyException e) {
            throw new Auth0Exception("JWTVerifyException during decodeToken operation", e);
        }
    }
}
