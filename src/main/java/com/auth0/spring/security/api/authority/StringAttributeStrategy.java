package com.auth0.spring.security.api.authority;

import com.auth0.jwt.internal.org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

public class StringAttributeStrategy implements AuthorityStrategy {

    private final String attribute;

    public StringAttributeStrategy(final String attribute) {
        if (StringUtils.isEmpty(attribute)) {
            throw new IllegalArgumentException("Attribute must be a valid string");
        }
        this.attribute = attribute;
    }

    protected String getAttribute() {
        return attribute;
    }

    @Override
    public Collection<String> getAuthorities(final Map<String, Object> map) {
        final String authoritiesStr = (String) map.get(getAttribute());
        return (authoritiesStr != null) ? Arrays.asList(authoritiesStr.split("\\s+")) : null;
    }

}
