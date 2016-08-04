package com.auth0.spring.security.api;

import com.auth0.jwt.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 *  Auth0 Security Config that wires together dependencies required
 *
 *  Applications are expected to extend this Config
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0ApiSecurityEnabled")
public class Auth0SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value(value = "${auth0.domain}")
    protected String domain;

    @Value(value = "${auth0.issuer}")
    protected String issuer;

    @Value(value = "${auth0.clientId}")
    protected String clientId;

    @Value(value = "${auth0.clientSecret}")
    protected String clientSecret;

    @Value(value = "${auth0.securedRoute}")
    protected String securedRoute;

    @Value(value = "${auth0.authorityStrategy}")
    protected String authorityStrategy;

    @Value(value = "${auth0.base64EncodedSecret}")
    protected boolean base64EncodedSecret;

    /**
     * default to HS256 for backwards compatibility
     */
    @Value(value = "${auth0.signingAlgorithm:HS256}")
    protected String signingAlgorithm;

    /**
     * default to empty string as HS256 is default
     */
    @Value(value = "${auth0.publicKeyPath:}")
    protected String publicKeyPath;

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
        // First check the authority strategy configured for the API
        if (!Auth0AuthorityStrategy.contains(this.authorityStrategy)) {
            throw new IllegalStateException("Configuration error, illegal authority strategy");
        }
        final Auth0AuthorityStrategy authorityStrategy = Auth0AuthorityStrategy.valueOf(this.authorityStrategy);
        final Auth0AuthenticationProvider authenticationProvider = new Auth0AuthenticationProvider();
        authenticationProvider.setDomain(domain);
        authenticationProvider.setIssuer(issuer);
        authenticationProvider.setClientId(clientId);
        authenticationProvider.setClientSecret(clientSecret);
        authenticationProvider.setSecuredRoute(securedRoute);
        authenticationProvider.setAuthorityStrategy(authorityStrategy);
        authenticationProvider.setBase64EncodedSecret(base64EncodedSecret);
        authenticationProvider.setSigningAlgorithm(Algorithm.valueOf(this.signingAlgorithm));
        authenticationProvider.setPublicKeyPath(this.publicKeyPath);
        return authenticationProvider;
    }

    @Bean(name = "auth0EntryPoint")
    public Auth0AuthenticationEntryPoint auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    @Bean(name = "auth0Filter")
    public Auth0AuthenticationFilter auth0AuthenticationFilter(final Auth0AuthenticationEntryPoint entryPoint) {
        final Auth0AuthenticationFilter filter = new Auth0AuthenticationFilter();
        filter.setEntryPoint(entryPoint);
        return filter;
    }

    /**
     * We do this to ensure our Filter is only loaded once into Application Context
     *
     * If using Spring Boot, any GenericFilterBean in the context will be automatically added to the filter chain.
     * Since we want to support Servlet 2.x and 3.x we should not extend OncePerRequestFilter therefore instead
     * we explicitly define FilterRegistrationBean and disable.
     *
     */
    @Bean(name = "auth0AuthenticationFilterRegistration")
    public FilterRegistrationBean auth0AuthenticationFilterRegistration(final Auth0AuthenticationFilter filter) {
        final FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(filter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(auth0AuthenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        // Disable CSRF for JWT usage
        http.csrf().disable();

        // Add Auth0 Authentication Filter
        http.addFilterAfter(auth0AuthenticationFilter(auth0AuthenticationEntryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(simpleCORSFilter(), Auth0AuthenticationFilter.class);

        // Apply the Authentication and Authorization Strategies your application endpoints require
        authorizeRequests(http);

        // STATELESS - we want re-authentication of JWT token on every request
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    /**
     * Lightweight default configuration that offers basic authorization checks for authenticated
     * users on secured endpoint, and sets up a Principal user object with granted authorities
     * <p>
     * For simple apps, this is sufficient, however for applications wishing to specify fine-grained
     * endpoint access restrictions, use Role / Group level endpoint authorization etc, then this configuration
     * should be disabled and a copy, augmented with your own requirements provided. See Sample app for example
     *
     * Override this function in subclass to apply custom authentication / authorization
     * strategies to your application endpoints
     */
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(securedRoute).authenticated()
                .antMatchers("/**").permitAll();
    }

}