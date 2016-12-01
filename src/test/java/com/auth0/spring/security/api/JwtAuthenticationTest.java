package com.auth0.spring.security.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.hamcrest.Matchers;
import org.hamcrest.collection.IsCollectionWithSize;
import org.hamcrest.collection.IsEmptyCollection;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class JwtAuthenticationTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Algorithm hmacAlgorithm;

    @Before
    public void setUp() throws Exception {
        hmacAlgorithm = Algorithm.HMAC256("secret");
    }

    @Test
    public void shouldCreateNonAuthenticatedInstance() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(false));
    }

    @Test
    public void shouldCreateAuthenticatedInstance() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);
        JWTVerifier verifier = JWT.require(hmacAlgorithm).build();

        JwtAuthentication auth = new JwtAuthentication(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(true));
    }

    @Test
    public void shouldAllowToChangeAuthenticatedToFalse() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);
        JWTVerifier verifier = JWT.require(hmacAlgorithm).build();

        JwtAuthentication auth = new JwtAuthentication(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(true));

        auth.setAuthenticated(false);
        assertThat(auth.isAuthenticated(), is(false));
    }

    @Test
    public void shouldNotAllowToChangeAuthenticatedToTrue() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(false));

        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Must create a new instance to specify that the authentication is valid");
        auth.setAuthenticated(true);
    }

    @Test
    public void shouldGetKeyId() throws Exception {
        String token = JWT.create()
                .withClaim("kid", "my-key-id")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is("my-key-id"));
    }

    @Test
    public void shouldGetNullKeyIdOnMissingKeyIdClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is(nullValue()));
    }

    @Test
    public void shouldGetStringToken() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getToken(), is(token));
    }

    @Test
    public void shouldGetStringTokenAsCredentials() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
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

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getDetails(), is(notNullValue()));
        assertThat(auth.getDetails(), is(instanceOf(DecodedJWT.class)));
    }

    @Test
    public void shouldGetSubjectAsPrincipal() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(notNullValue()));
        assertThat(auth.getPrincipal(), is(instanceOf(String.class)));
        assertThat(auth.getPrincipal(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullPrincipalOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(nullValue()));
    }

    @Test
    public void shouldGetSubjectAsName() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(notNullValue()));
        assertThat(auth.getName(), is(instanceOf(String.class)));
        assertThat(auth.getName(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullNameOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(nullValue()));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnMissingScopeClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnEmptyScopeClaim() throws Exception {
        String token = JWT.create()
                .withClaim("scope", "   ")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetScopeAsAuthorities() throws Exception {
        String token = JWT.create()
                .withClaim("scope", "auth0 auth10")
                .sign(hmacAlgorithm);

        JwtAuthentication auth = new JwtAuthentication(token);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(2)));

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
        assertThat(authorities.get(0), is(notNullValue()));
        assertThat(authorities.get(0).getAuthority(), is("auth0"));
        assertThat(authorities.get(1), is(notNullValue()));
        assertThat(authorities.get(1).getAuthority(), is("auth10"));
    }
}