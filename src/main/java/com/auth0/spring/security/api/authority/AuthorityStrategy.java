package com.auth0.spring.security.api.authority;

import java.util.Collection;
import java.util.Map;

/**
 * The strategy used to extract "Role" info
 *
 * This may be Groups, Roles, Scope or even custom defined
 *
 */
public interface AuthorityStrategy {

    Collection<String> getAuthorities(final Map<String, Object> map);

}
