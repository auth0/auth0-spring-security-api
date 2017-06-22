package com.auth0.spring.security.api.rsa;

import com.auth0.Auth0Exception;
import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import com.auth0.spring.security.api.Auth0TokenHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class Auth0RSATokenHelper extends Auth0TokenHelper<Object> {

    @SuppressWarnings("unchecked")
    @Override
    public String generateToken(Object object, String issuer, String audience, long expiration) {
        Assert.isInstanceOf(Map.class, object, "Claims object is not a java.util.Map");
        try {
            PrivateKey rsa = PemUtils.readPrivateKeyFromFile("src/test/resources/rsa-private.pem", "RSA");
            final JWTSigner jwtSigner = new JWTSigner(rsa);
            final HashMap<String, Object> claims = new HashMap<>();
            claims.putAll((Map) object);
            claims.put("exp", expiration);
            claims.put("iss", issuer);
            claims.put("aud", audience);
            JWTSigner.Options options = new JWTSigner.Options().setAlgorithm(Algorithm.RS256);
            return jwtSigner.sign(claims, options);
        } catch (Exception e) {
            throw new Auth0Exception("Token generation error", e);
        }
    }

    @Override
    public Object decodeToken(String token) {
        try {
            PublicKey rsa = PemUtils.readPublicKeyFromFile("resources/rsa-public.pem", "RSA");
            final JWTVerifier jwtVerifier = new JWTVerifier(rsa, getClientId());
            final Map<String, Object> verify = jwtVerifier.verify(token);
            final String payload = (String) verify.get("$");
            return new ObjectMapper().readValue(payload, Map.class);
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
