package com.auth0.spring.security.api;


import com.auth0.spring.security.api.authority.AuthorityStrategy;
import com.auth0.spring.security.api.authority.ListAttributeStrategy;
import com.auth0.spring.security.api.authority.StringAttributeStrategy;

/**
 * The authority strategy being used - can be either ROLES, GROUPS, or SCOPE
 *
 * For API Resource Server using JWT Access Tokens - `scope` is the default.
 * This is a claim added to the JWT Access token whose values are the scope
 * values representing the permissions granted.
 */
public enum Auth0AuthorityStrategy {

    GROUPS("groups", new ListAttributeStrategy("groups")),
    ROLES("roles", new ListAttributeStrategy("roles")),
    SCOPE("scope", new StringAttributeStrategy("scope"));

    private final String name;
    private final AuthorityStrategy strategy;

    Auth0AuthorityStrategy(final String name, final AuthorityStrategy strategy) {
        this.name = name;
        this.strategy = strategy;
    }

    public AuthorityStrategy getStrategy() {
      return this.strategy;
    }

    @Override
    public String toString() {
        return this.name;
    }

    /**
     * Indicates whether this Authority Strategy contains the value supplied
     * @param value the value to check
     * @return boolean indicating whether found
     */
    public static boolean contains(final String value) {
        for (final Auth0AuthorityStrategy authorityStrategy : values()) {
            if (authorityStrategy.name().equals(value)) {
                return true;
            }
        }
        return false;
    }

}
