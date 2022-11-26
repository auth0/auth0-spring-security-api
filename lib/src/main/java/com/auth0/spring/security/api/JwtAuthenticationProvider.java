package com.auth0.spring.security.api;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.spring.security.api.authentication.JwtAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.security.interfaces.RSAPublicKey;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationProvider.class);

    private final byte[] secret;
    private final String[] issuers;
    private final String audience;
    private final JwkProvider jwkProvider;

    private long leeway = 0;

    public JwtAuthenticationProvider(byte[] secret, String issuer, String audience) {
        this(secret, new String[]{issuer}, audience);
    }

    public JwtAuthenticationProvider(JwkProvider jwkProvider, String issuer, String audience) {
        this(jwkProvider, new String[]{issuer}, audience);
    }

    public JwtAuthenticationProvider(byte[] secret, String[] issuers, String audience) {
        this.secret = secret;
        this.issuers = issuers;
        this.audience = audience;
        this.jwkProvider = null;
    }

    public JwtAuthenticationProvider(JwkProvider jwkProvider,  String[] issuers, String audience) {
        this.jwkProvider = jwkProvider;
        this.secret = null;
        this.issuers = issuers;
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
            final Authentication jwtAuth = jwt.verify(jwtVerifier(jwt));
            logger.info("Authenticated with jwt with scopes {}", jwtAuth.getAuthorities());
            return jwtAuth;
        } catch (JWTVerificationException e) {
            throw new BadCredentialsException("Not a valid token", e);
        }
    }

    /**
     * Allow a leeway to use on the JWT verification.
     *
     * @param leeway the leeway value to use expressed in seconds.
     * @return this same provider instance to chain calls.
     */
    @SuppressWarnings("unused")
    public JwtAuthenticationProvider withJwtVerifierLeeway(long leeway) {
        this.leeway = leeway;
        return this;
    }

    private JWTVerifier jwtVerifier(JwtAuthentication authentication) throws AuthenticationException {
        if (secret != null) {
            return providerForHS256(secret, issuers, audience, leeway);
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
            return providerForRS256((RSAPublicKey) jwk.getPublicKey(), issuers, audience, leeway);
        } catch (SigningKeyNotFoundException e) {
            throw new AuthenticationServiceException("Could not retrieve jwks from issuer", e);
        } catch (InvalidPublicKeyException e) {
            throw new AuthenticationServiceException("Could not retrieve public key from issuer", e);
        } catch (JwkException e) {
            throw new AuthenticationServiceException("Cannot authenticate with jwt", e);
        }
    }

    private static JWTVerifier providerForRS256(RSAPublicKey publicKey, String[] issuers, String audience, long leeway) {
        return JWT.require(Algorithm.RSA256(publicKey, null))
                .withIssuer(issuers)
                .withAudience(audience)
                .acceptLeeway(leeway)
                .build();
    }

    private static JWTVerifier providerForHS256(byte[] secret, String[] issuers, String audience, long leeway) {
        return JWT.require(Algorithm.HMAC256(secret))
                .withIssuer(issuers)
                .withAudience(audience)
                .acceptLeeway(leeway)
                .build();
    }
}
