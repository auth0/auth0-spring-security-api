package com.auth0.spring.security.api;

import com.auth0.jwk.*;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Map;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationProvider.class);

    private final byte[] secret;
    private final String issuer;
    private final String audience;
    private final JwkProvider jwkProvider;

    public JwtAuthenticationProvider(byte[] secret, String issuer, String audience) {
        this.secret = secret;
        this.issuer = issuer;
        this.audience = audience;
        this.jwkProvider = null;
    }

    public JwtAuthenticationProvider(JwkProvider jwkProvider, String issuer, String audience) {
        this.jwkProvider = jwkProvider;
        this.secret = null;
        this.issuer = issuer;
        this.audience = audience;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        JwtAuthentication jwt = (JwtAuthentication) authentication;
        try {
            final String token = jwt.getToken();
            final JWTVerifier verifier = jwtVerifier(jwt);
            final Map<String, Object> decoded = verifier.verify(token);
            final JwtAuthentication jwtAuth = new JwtAuthentication(token, decoded);
            logger.info("Authenticated with jwt with scopes {}", jwtAuth.getAuthorities());
            return jwtAuth;
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException | JWTVerifyException e) {
            throw new BadCredentialsException("Not a valid token", e);
        }
    }

    private JWTVerifier jwtVerifier(JwtAuthentication authentication) throws AuthenticationException {
        if (secret != null) {
            return providerForHS256(secret, issuer, audience);
        }
        final String kid = authentication.getKeyId();
        if (kid == null) {
            throw new BadCredentialsException("No kid found in jwt");
        }
        if (jwkProvider == null) {
            throw new AuthenticationServiceException("Missing jwk provider");
        }
        try {
            final Jwk jwk = jwkProvider.get(kid);
            return providerForRS256(jwk.getPublicKey(), issuer, audience);
        } catch (SigningKeyNotFoundException e) {
            throw new AuthenticationServiceException("Could not retrieve jwks from issuer", e);
        } catch (InvalidPublicKeyException e) {
            throw new AuthenticationServiceException("Could not retrieve public key from issuer", e);
        } catch (JwkException e) {
            throw new AuthenticationServiceException("Cannot authenticate with jwt", e);
        }
    }

    private static JWTVerifier providerForRS256(PublicKey key, String issuer, String audience) {
        return new JWTVerifier(key, audience, issuer);
    }

    private static JWTVerifier providerForHS256(byte[] secret, String issuer, String audience) {
        return new JWTVerifier(secret, audience, issuer);
    }
}
