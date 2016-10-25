package com.auth0.spring.security.api;

import com.auth0.jwt.Algorithm;
import com.auth0.spring.security.api.authority.AuthorityStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
 * Holds the default configuration for the library
 * Applications are expected to extend this configuration on as-needed basis
 *
 * Extend this configuration in your own subclass and override specific functions to apply your own
 * behaviour as required eg. to apply custom authentication / authorization strategies to your application endpoints
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0ApiSecurityEnabled")
public class Auth0SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * This is your auth0 domain (tenant you have created when registering with auth0 - account name)
     */
    @Value(value = "${auth0.domain}")
    protected String domain;

    /**
     * This is the issuer of the JWT Token (typically full URL of your auth0 tenant account
     * eg. https://{tenant_name}.auth0.com/
     */
    @Value(value = "${auth0.issuer}")
    protected String issuer;

    /**
     * This is the client id of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${auth0.clientId}")
    protected String clientId;

    /**
     * This is the client secret of your auth0 application (see Settings page on auth0 dashboard)
     */
    @Value(value = "${auth0.clientSecret}")
    protected String clientSecret;

    /**
     * This is the URL pattern to secure a URL endpoint. Should start with `/`
     */
    @Value(value = "${auth0.securedRoute}")
    protected String securedRoute;

    /**
     * The authority strategy being used - can be either ROLES, GROUPS or SCOPE
     * whose values are the scope values representing the permissions granted.
     * For the Auth0 Resource Server API - the default is SCOPE
     */
    @Value(value = "${auth0.authorityStrategy}")
    protected String authorityStrategy;

    /**
     * This is a boolean value indicating whether the Secret used to verify the JWT is base64 encoded. Default is `true`
     */
    @Value(value = "${auth0.base64EncodedSecret}")
    protected boolean base64EncodedSecret;

    /**
     * This is signing algorithm to verify signed JWT token. Use `HS256` or `RS256`.
     * Default to HS256 for backwards compatibility
     */
    @Value(value = "${auth0.signingAlgorithm:HS256}")
    protected String signingAlgorithm;

    /**
     * This is the path location to the public key stored locally on disk / inside your application War file WEB-INF directory.
     * Should always be set when using `RS256`.
     */
    @Value(value = "${auth0.publicKeyPath:}")
    protected String publicKeyPath;

    @Autowired
    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Bean(name = "auth0AuthenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Factory for CORSFilter
     */
    @Bean
    public Auth0CORSFilter simpleCORSFilter() {
        return new Auth0CORSFilter();
    }

    /**
     * Factory for AuthorityStrategy
     */
    @Bean(name = "authorityStrategy")
    public AuthorityStrategy authorityStrategy() {
        if (!Auth0AuthorityStrategy.contains(this.authorityStrategy)) {
            throw new IllegalStateException("Configuration error, illegal authority strategy");
        }
        return Auth0AuthorityStrategy.valueOf(this.authorityStrategy).getStrategy();
    }

    /**
     * Factory for AuthenticationProvider
     */
    @Bean(name = "auth0AuthenticationProvider")
    public Auth0AuthenticationProvider auth0AuthenticationProvider() {
        final Auth0AuthenticationProvider authenticationProvider = new Auth0AuthenticationProvider();
        authenticationProvider.setDomain(domain);
        authenticationProvider.setIssuer(issuer);
        authenticationProvider.setClientId(clientId);
        authenticationProvider.setClientSecret(clientSecret);
        authenticationProvider.setSecuredRoute(securedRoute);
        authenticationProvider.setAuthorityStrategy(authorityStrategy());
        authenticationProvider.setBase64EncodedSecret(base64EncodedSecret);
        authenticationProvider.setSigningAlgorithm(Algorithm.valueOf(this.signingAlgorithm));
        authenticationProvider.setPublicKeyPath(this.publicKeyPath);
        return authenticationProvider;
    }

    /**
     * Factory for Auth0AuthenticationEntryPoint
     */
    @Bean(name = "auth0EntryPoint")
    public Auth0AuthenticationEntryPoint auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    /**
     * Factory for Auth0AuthenticationFilter
     */
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
    public void configure(final WebSecurity web) throws Exception {
        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**");
    }

    /**
     * Http Security Configuration
     */
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
