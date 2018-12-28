package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.hamcrest.Matchers;
import org.hamcrest.collection.IsEmptyCollection;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;

public class PreAuthenticatedAuthenticationJsonWebTokenTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Algorithm hmacAlgorithm;
    private AuthenticationJsonWebTokenFactory tokenFactory;

    @Before
    public void setUp() throws Exception {
        hmacAlgorithm = Algorithm.HMAC256("secret");
        tokenFactory = new AuthenticationJsonWebTokenFactory();
    }

    @Test
    public void shouldCreateNonAuthenticatedInstance() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken) tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(false));
    }

    @Test
    public void shouldAlwaysBeNonAuthenticated() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);

        assertThat(auth.isAuthenticated(), is(false));
        auth.setAuthenticated(true);
        assertThat(auth.isAuthenticated(), is(false));
    }

    @Test
    public void shouldGetKeyId() throws Exception {
        Map<String, Object> keyIdHeader = Collections.singletonMap("kid", (Object) "key-id");
        String token = JWT.create()
                .withHeader(keyIdHeader)
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is("key-id"));
    }

    @Test
    public void shouldGetNullKeyIdOnMissingKeyIdClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is(nullValue()));
    }

    @Test
    public void shouldGetStringToken() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getToken(), is(token));
    }

    @Test
    public void shouldGetStringTokenAsCredentials() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getCredentials(), is(notNullValue()));
        assertThat(auth.getCredentials(), is(instanceOf(String.class)));
        assertThat(auth.getCredentials(), Matchers.<Object>is(token));
    }

    @Test
    public void shouldGetJWTAsDetails() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getDetails(), is(notNullValue()));
        assertThat(auth.getDetails(), is(instanceOf(DecodedJWT.class)));
    }

    @Test
    public void shouldGetSubjectAsPrincipal() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(notNullValue()));
        assertThat(auth.getPrincipal(), is(instanceOf(String.class)));
        assertThat(auth.getPrincipal(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullPrincipalOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(nullValue()));
    }

    @Test
    public void shouldGetSubjectAsName() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(notNullValue()));
        assertThat(auth.getName(), is(instanceOf(String.class)));
        assertThat(auth.getName(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullNameOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(nullValue()));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnMissingScopeClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldAlwaysGetEmptyAuthorities() throws Exception {
        String token = JWT.create()
                .withClaim("scope", "read:users add:users")
                .sign(hmacAlgorithm);

        PreAuthenticatedAuthenticationJsonWebToken auth = (PreAuthenticatedAuthenticationJsonWebToken)tokenFactory.usingToken(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

}