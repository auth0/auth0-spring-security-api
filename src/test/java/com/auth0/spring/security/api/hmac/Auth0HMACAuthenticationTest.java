package com.auth0.spring.security.api.hmac;

import org.junit.Test;

import java.util.Calendar;
import java.util.Date;

import static com.auth0.spring.security.api.Auth0TokenHelper.VALID_AUDIENCE;
import static com.auth0.spring.security.api.Auth0TokenHelper.VALID_ISSUER;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class Auth0HMACAuthenticationTest extends AbstractAuth0AuthenticationTest {

    @Test
    public void shouldReturn403WithoutToken() throws Exception {
        callUrlWithoutToken("/secured").andExpect(status().isForbidden());
    }

    @Test
    public void shouldReturn401ForAnInvalidToken() throws Exception {
        callUrlWithToken("/secured", "a.b.c").andExpect(status().isUnauthorized());
    }

    @Test
    public void shouldReturn401ForATokenThatHasExpired() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, -1);
        String token = generateTokenWithExpirationDate(VALID_ISSUER, VALID_AUDIENCE, c.getTimeInMillis() / 1000L);
        callUrlWithToken("/secured", token).andExpect(status().isUnauthorized());
    }

    @Test
    public void shouldReturn401ForATokenWithInvalidIssuer() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        String token = generateTokenWithExpirationDate("not-valid", VALID_AUDIENCE, c.getTimeInMillis() / 1000L);
        callUrlWithToken("/secured", token).andExpect(status().isUnauthorized());
    }

    @Test
    public void shouldReturn401ForATokenWithInvalidAudience() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        String token = generateTokenWithExpirationDate(VALID_ISSUER, "not-valid", c.getTimeInMillis() / 1000L);
        callUrlWithToken("/secured", token).andExpect(status().isUnauthorized());
    }

    @Test
    public void shouldReturn200ForAValidToken() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        callUrlWithToken("/secured", generateTokenWithExpirationDate(VALID_ISSUER, VALID_AUDIENCE, c.getTimeInMillis() / 1000L)).andExpect(status().isOk());
    }

    @Test
    public void shouldReturn200ForAnUnsecuredUrl() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        callUrlWithToken("/unsecured", generateTokenWithExpirationDate(VALID_ISSUER, VALID_AUDIENCE, c.getTimeInMillis() / 1000L)).andExpect(status().isOk());
    }

}
