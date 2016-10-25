package com.auth0.spring.security.api;

import com.auth0.spring.security.api.authority.AuthorityStrategy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * Implementation of UserDetails in compliance with the decoded object returned by the Auth0 JWT
 */
public class Auth0UserDetails implements UserDetails {

    private static final long serialVersionUID = 2058797193125711681L;

    private Map<String, Object> details;
    private String username;
    private boolean emailVerified;
    private Collection<GrantedAuthority> authorities = null;


    @SuppressWarnings("unchecked")
    public Auth0UserDetails(final Map<String, Object> map, final AuthorityStrategy authorityStrategy) {
        this.details = map;
        if (map.containsKey("email")) {
            this.username = map.get("email").toString();
        } else if (map.containsKey("username")) {
            this.username = map.get("username").toString();
        } else if (map.containsKey("nickname")) {
            this.username = map.get("nickname").toString();
        } else if (map.containsKey("user_id")) {
            this.username = map.get("user_id").toString();
        } else {
            this.username = "UNKNOWN_USER";
        }
        if (map.containsKey("email") && map.containsKey("email_verified")) {
            this.emailVerified = Boolean.valueOf(map.get("email_verified").toString());
        }
        setupGrantedAuthorities(map, authorityStrategy);
    }

    private void setupGrantedAuthorities(final Map<String, Object> map, final AuthorityStrategy authorityStrategy) {
        this.authorities = new ArrayList<>();
        try {
            final Collection<String> authorities = authorityStrategy.getAuthorities(map);
            if (authorities != null) {
                 for (final String authority : authorities) {
                    this.authorities.add(new SimpleGrantedAuthority(authority));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Will return UnsupportedOperationException
     */
    public String getPassword() {
        return null;
    }

    /**
     * Gets the email if it exists otherwise it returns the user_id
     */
    public String getUsername() {
        return username;
    }

    /**
     * Indicates whether the user's account has expired. An expired account cannot be
     * authenticated.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user's account is valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. A locked user cannot be
     * authenticated.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) has expired. Expired
     * credentials prevent authentication.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user's credentials are valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Will return true if the email is verified, otherwise it will return false
     */
    @Override
    public boolean isEnabled() {
        return emailVerified;
    }

    /**
     * Will return the details of the attribute of JWT decoded token if it exists or null otherwise.
     * Example getAuth0Attribute("email"), getAuth0Attribute("picture")....
     *
     * @return return the details of the JWT decoded token if it exists  or null otherwise
     */
    public Object getAuth0Attribute(String attributeName) {
        return details.get(attributeName);
    }


}
