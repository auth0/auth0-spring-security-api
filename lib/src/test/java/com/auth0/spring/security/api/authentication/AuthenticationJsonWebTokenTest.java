package com.auth0.spring.security.api.authentication;

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
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class AuthenticationJsonWebTokenTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private Algorithm hmacAlgorithm;
    private JWTVerifier verifier;

    @Before
    public void setUp() throws Exception {
        hmacAlgorithm = Algorithm.HMAC256("secret");
        verifier = JWT.require(hmacAlgorithm).build();
    }

    @Test
    public void shouldCreateAuthenticatedInstance() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(true));
    }

    @Test
    public void shouldAllowToChangeAuthenticatedToFalse() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(true));

        auth.setAuthenticated(false);
        assertThat(auth.isAuthenticated(), is(false));
    }

    @Test
    public void shouldNotAllowToChangeAuthenticatedToTrue() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        JWTVerifier verifier = JWT.require(hmacAlgorithm).build();
        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.isAuthenticated(), is(true));

        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Must create a new instance to specify that the authentication is valid");
        auth.setAuthenticated(true);
    }

    @Test
    public void shouldGetKeyId() throws Exception {
        Map<String, Object> keyIdHeader = Collections.singletonMap("kid", (Object) "key-id");
        String token = JWT.create()
                .withHeader(keyIdHeader)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is("key-id"));
    }

    @Test
    public void shouldGetNullKeyIdOnMissingKeyIdClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getKeyId(), is(nullValue()));
    }

    @Test
    public void shouldGetStringToken() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getToken(), is(token));
    }

    @Test
    public void shouldGetStringTokenAsCredentials() throws Exception {
        String token = JWT.create()
                .withIssuer("auth0")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
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

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getDetails(), is(notNullValue()));
        assertThat(auth.getDetails(), is(instanceOf(DecodedJWT.class)));
    }

    @Test
    public void shouldGetSubjectAsPrincipal() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(notNullValue()));
        assertThat(auth.getPrincipal(), is(instanceOf(String.class)));
        assertThat(auth.getPrincipal(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullPrincipalOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getPrincipal(), is(nullValue()));
    }

    @Test
    public void shouldGetSubjectAsName() throws Exception {
        String token = JWT.create()
                .withSubject("1234567890")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(notNullValue()));
        assertThat(auth.getName(), is(instanceOf(String.class)));
        assertThat(auth.getName(), Matchers.<Object>is("1234567890"));
    }

    @Test
    public void shouldGetNullNameOnMissingSubjectClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getName(), is(nullValue()));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnMissingScopeClaim() throws Exception {
        String token = JWT.create()
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnEmptyScopeClaim() throws Exception {
        String token = JWT.create()
                .withClaim("scope", "   ")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetScopeAsAuthorities() throws Exception {
        String token = JWT.create()
                .withClaim("scope", "auth0 auth10")
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));

        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        assertThat(authorities, is(notNullValue()));
        assertThat(authorities, is(IsCollectionWithSize.hasSize(4)));
        assertThat(authorities, containsInAnyOrder(
                hasProperty("authority", is("auth0")),
                hasProperty("authority", is("auth10")),
                hasProperty("authority", is("SCOPE_auth0")),
                hasProperty("authority", is("SCOPE_auth10"))
        ));
    }

    @Test
    public void shouldGetEmptyAuthoritiesOnEmptyPermissionsClaim() throws Exception {
        String token = JWT.create()
                .withArrayClaim("permissions", new String[]{})
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsEmptyCollection.empty()));
    }

    @Test
    public void shouldGetPermissionsAsAuthorities() throws Exception {
        String[] permissionsClaim = {"read:permission", "write:permission"};
        String token = JWT.create()
                .withArrayClaim("permissions", permissionsClaim)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier);
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(2)));

        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        assertThat(authorities, IsCollectionWithSize.hasSize(2));
        assertThat(authorities, containsInAnyOrder(
                hasProperty("authority", is("PERMISSION_" + permissionsClaim[0])),
                hasProperty("authority", is("PERMISSION_" + permissionsClaim[1]))
        ));
    }

    @Test
    public void shouldGetCustomArrayClaimsAsAuthorities() throws Exception {
        String[] customClaims = {"write:admin", "read:admin"};
        String token = JWT.create()
                .withArrayClaim("customArrayClaim", customClaims)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier, Collections.singletonList("customArrayClaim"));
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(2)));

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
        assertThat(authorities.get(0), is(notNullValue()));
        assertThat(authorities.get(0).getAuthority(), is("customArrayClaim_" + customClaims[0]));
        assertThat(authorities.get(1), is(notNullValue()));
        assertThat(authorities.get(1).getAuthority(), is("customArrayClaim_" + customClaims[1]));
    }

    @Test
    public void shouldGetCustomStringClaimsAsAuthorities() throws Exception {
        String customClaim = "admin";
        String token = JWT.create()
                .withClaim("customStringClaim", customClaim)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier, Collections.singletonList("customStringClaim"));
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(1)));

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
        assertThat(authorities.get(0), is(notNullValue()));
        assertThat(authorities.get(0).getAuthority(), is("customStringClaim_" + customClaim));
    }

    @Test
    public void shouldGetCustomStringClaimsMultipleAsAuthorities() throws Exception {
        String customClaim = "admin:write admin:read";
        String token = JWT.create()
                .withClaim("customStringClaim", customClaim)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier, Collections.singletonList("customStringClaim"));
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(2)));

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
        assertThat(authorities.get(0), is(notNullValue()));
        assertThat(authorities.get(0).getAuthority(), is("customStringClaim_admin:write"));
        assertThat(authorities.get(1), is(notNullValue()));
        assertThat(authorities.get(1).getAuthority(), is("customStringClaim_admin:read"));
    }

    @Test
    public void shouldGetCustomArrayClaimsDifferentTypesAsAuthorities() throws Exception {
        Long[] customClaims = {41L, 42L};
        String token = JWT.create()
                .withArrayClaim("customArrayClaim", customClaims)
                .sign(hmacAlgorithm);

        AuthenticationJsonWebToken auth = new AuthenticationJsonWebToken(token, verifier, Collections.singletonList("customArrayClaim"));
        assertThat(auth, is(notNullValue()));
        assertThat(auth.getAuthorities(), is(notNullValue()));
        assertThat(auth.getAuthorities(), is(IsCollectionWithSize.hasSize(2)));

        ArrayList<GrantedAuthority> authorities = new ArrayList<>(auth.getAuthorities());
        assertThat(authorities, containsInAnyOrder(
                hasProperty("authority", is("customArrayClaim_" + customClaims[0])),
                hasProperty("authority", is("customArrayClaim_" + customClaims[1]))
        ));
    }
}