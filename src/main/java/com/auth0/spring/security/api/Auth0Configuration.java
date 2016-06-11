package com.auth0.spring.security.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * Lightweight default configuration that offers basic authorization checks for authenticated
 * users on secured endpoint, and sets up a Principal user object with granted authorities
 *
 * For simple apps, this is sufficient, however for applications wishing to specify fine-grained
 * endpoint access restrictions, use Role / Group level endpoint authorization etc, then this configuration
 * should be disabled and a copy, augmented with your own requirements provided. See Sample app for example
 *
 */
@Configuration
@EnableWebSecurity(debug = true)
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0ApiSecurityEnabled")
public class Auth0Configuration extends WebSecurityConfigurerAdapter {

    @Value(value = "${auth0.clientId}")
    private String clientId;

    @Value(value = "${auth0.clientSecret}")
    private String clientSecret;

    @Value(value = "${auth0.securedRoute}")
    private String securedRoute;

    @Autowired
    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Bean(name = "auth0AuthenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public Auth0CORSFilter simpleCORSFilter() {
        return new Auth0CORSFilter();
    }

    @Bean(name = "auth0AuthenticationProvider")
    public Auth0AuthenticationProvider auth0AuthenticationProvider() {
        final Auth0AuthenticationProvider authenticationProvider = new Auth0AuthenticationProvider();
        authenticationProvider.setClientId(clientId);
        authenticationProvider.setClientSecret(clientSecret);
        authenticationProvider.setSecuredRoute(securedRoute);
        return authenticationProvider;
    }

    @Bean(name = "auth0EntryPoint")
    public Auth0AuthenticationEntryPoint auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    @Bean(name = "auth0Filter")
    public Auth0AuthenticationFilter auth0AuthenticationFilter(Auth0AuthenticationEntryPoint entryPoint) {
        final Auth0AuthenticationFilter filter = new Auth0AuthenticationFilter();
        filter.setEntryPoint(entryPoint);
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(auth0AuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Disable CSRF for JWT usage
        http
                .csrf().disable()
                .addFilterAfter(auth0AuthenticationFilter(auth0AuthenticationEntryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(simpleCORSFilter(), Auth0AuthenticationFilter.class)
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers(securedRoute).authenticated();
        // ensure JWT should be sent with every request - no session
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}