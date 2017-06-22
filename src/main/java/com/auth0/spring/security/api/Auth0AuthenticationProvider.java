package com.auth0.spring.security.api;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTVerifyException;
import com.auth0.spring.security.api.authority.AuthorityStrategy;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.Validate;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Map;

import static com.auth0.jwt.pem.PemReader.readPublicKey;

/**
 * Class that verifies the JWT token and when valid, it will set
 * the UserDetails in the authentication object
 */
public class Auth0AuthenticationProvider implements AuthenticationProvider, InitializingBean {

    private static final AuthenticationException AUTH_ERROR = new Auth0TokenException("Authentication Error");

    private JWTVerifier jwtVerifier;
    private String domain;
    private String issuer;
    private String clientId;
    private String clientSecret;
    private String securedRoute;
    private boolean base64EncodedSecret;
    private AuthorityStrategy authorityStrategy;
    private Algorithm signingAlgorithm;
    private String publicKeyPath;

    /**
     * Performs authentication with the same contract as
     * {@link org.springframework.security.authentication.AuthenticationManager#authenticate(Authentication)}
     *
     * Verifies the JWT Token on every request and only creates Principal if not already authenticated
     *
     * @param authentication the authentication request object.
     *
     * @return a fully authenticated object including credentials.
     * @throws AuthenticationException if authentication fails.
     */
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String token = ((Auth0JWTToken) authentication).getJwt();
        try {
            final Auth0JWTToken tokenAuth = ((Auth0JWTToken) authentication);
            final Map<String, Object> decoded = jwtVerifier.verify(token);
            tokenAuth.setAuthenticated(true);
            tokenAuth.setPrincipal(new Auth0UserDetails(decoded, authorityStrategy));
            tokenAuth.setDetails(decoded);
            return authentication;
        } catch (InvalidKeyException e) {
            throw new Auth0TokenException("InvalidKeyException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new Auth0TokenException("NoSuchAlgorithmException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (IllegalStateException e) {
            throw new Auth0TokenException("IllegalStateException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (SignatureException e) {
            throw new Auth0TokenException("SignatureException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (IOException e) {
            throw new Auth0TokenException("IOException thrown while decoding JWT token " + e.getLocalizedMessage());
        } catch (JWTVerifyException e) {
            throw new Auth0TokenException("JWTVerifyException thrown while decoding JWT token " + e.getLocalizedMessage());
        }
    }

    public boolean supports(Class<?> authentication) {
        return Auth0JWTToken.class.isAssignableFrom(authentication);
    }

    /**
     * Initialises configuration setup for the authentication provider
     */
    public void afterPropertiesSet() throws Exception {
        if ((clientSecret == null) || (clientId == null)) {
            throw new IllegalStateException("client secret and client id are not set for Auth0AuthenticationProvider");
        }
        if (securedRoute == null) {
            throw new IllegalStateException("You must set which route pattern is used to check for users so that they must be authenticated");
        }
        switch (signingAlgorithm) {
            case HS256:
            case HS384:
            case HS512:
                // Auth0 Client Secrets are currently Base64 encoded, Resource Server Signing Secret is NOT Base64 encoded
                if (base64EncodedSecret) {
                    new Base64(true);
                    jwtVerifier = new JWTVerifier(Base64.decodeBase64(clientSecret), clientId, issuer);
                } else {
                    jwtVerifier = new JWTVerifier(clientSecret, clientId, issuer);
                }
                return;
            case RS256:
            case RS384:
            case RS512:
                Validate.notEmpty(publicKeyPath);
                try {
                    final ClassLoader classLoader = getClass().getClassLoader();
                    final File file = new File(classLoader.getResource(publicKeyPath).getFile());
                    final String publicKeyRealPath = file.getAbsolutePath();
//                    final String publicKeyRealPath = servletContext.getRealPath(publicKeyPath);
                    final PublicKey publicKey = readPublicKey(publicKeyRealPath);
                    Validate.notNull(publicKey);
                    jwtVerifier = new JWTVerifier(publicKey, clientId, issuer);
                    return;
                } catch (Exception e) {
                    throw new IllegalStateException(e.getMessage(), e.getCause());
                }
            default:
                throw new IllegalStateException("Unsupported signing method: " + signingAlgorithm.getValue());
        }
    }

    protected String getDomain() {
        return domain;
    }

    protected void setDomain(String domain) {
        this.domain = domain;
    }

    protected String getIssuer() {
        return issuer;
    }

    protected void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    protected String getClientId() {
        return clientId;
    }

    protected void setClientId(String clientId) {
        this.clientId = clientId;
    }

    protected String getClientSecret() {
        return clientSecret;
    }

    protected void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    protected String getSecuredRoute() {
        return securedRoute;
    }

    protected void setSecuredRoute(String securedRoute) {
        this.securedRoute = securedRoute;
    }

    protected AuthorityStrategy getAuthorityStrategy() {
        return authorityStrategy;
    }

    protected void setAuthorityStrategy(AuthorityStrategy authorityStrategy) {
        this.authorityStrategy = authorityStrategy;
    }

    protected boolean isBase64EncodedSecret() {
        return base64EncodedSecret;
    }

    protected void setBase64EncodedSecret(boolean base64EncodedSecret) {
        this.base64EncodedSecret = base64EncodedSecret;
    }

    protected Algorithm getSigningAlgorithm() {
        return signingAlgorithm;
    }

    protected void setSigningAlgorithm(Algorithm signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
    }

    protected String getPublicKeyPath() {
        return publicKeyPath;
    }

    protected void setPublicKeyPath(String publicKeyPath) {
        this.publicKeyPath = publicKeyPath;
    }
}
