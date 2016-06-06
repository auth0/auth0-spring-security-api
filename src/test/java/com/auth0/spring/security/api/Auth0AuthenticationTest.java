package com.auth0.spring.security.api;

import org.junit.Test;

import java.util.Calendar;
import java.util.Date;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class Auth0AuthenticationTest extends AbstractAuth0AuthenticationTest {

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
        String token = generateTokenWithExpirationDate(c.getTimeInMillis() / 1000L);
        callUrlWithToken("/secured", token).andExpect(status().isUnauthorized());
    }

    @Test
    public void shouldReturn200ForAValidToken() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        callUrlWithToken("/secured", generateTokenWithExpirationDate(c.getTimeInMillis() / 1000L)).andExpect(status().isOk());
    }

    @Test
    public void shouldReturn200ForAnUnsecuredUrl() throws Exception {
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.add(Calendar.DATE, 1);
        callUrlWithToken("/unsecured", generateTokenWithExpirationDate(c.getTimeInMillis() / 1000L)).andExpect(status().isOk());
    }

}
