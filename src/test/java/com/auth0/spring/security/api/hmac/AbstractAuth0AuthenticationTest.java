package com.auth0.spring.security.api.hmac;

import com.auth0.spring.security.api.Auth0SecurityConfig;
import com.auth0.spring.security.api.Auth0TokenHelper;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = {TestAuth0Configuration.class, Auth0SecurityConfig.class})
@WebAppConfiguration
public abstract class AbstractAuth0AuthenticationTest {

    @Autowired
    protected WebApplicationContext webContext;

    @Autowired(required = false) // suppresses erroneous warning
    private Auth0TokenHelper<Object> tokenHelper;

    protected MockMvc mockMvc;

    @Before
    public void setupMockMvc() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webContext)
                .apply(springSecurity())
                .build();
    }

    protected String generateTokenWithExpirationDate(String iss, String aud, long exp) throws Exception {
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put("email", "auth0@test.com");
        map.put("email_verified", true);
        return tokenHelper.generateToken(map, iss, aud, exp);
    }

    protected ResultActions callUrlWithoutToken(String url) throws Exception {
        return this.mockMvc.perform(get(url));
    }

    protected ResultActions callUrlWithToken(String url, String token) throws Exception {
        return this.mockMvc.perform(get(url).header("Authorization", "Bearer " + token));
    }

}
