package com.pamesh.security.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import lombok.Builder;

/**
 * Instantiates a new jwt authentication token.
 *
 * @author Pamesh Bansal
 */
@Builder
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 6884335304272396855L;

    /** The bearer token. */
    private final String bearerToken;

    /**
     * Instantiates a new jwt authentication token.
     *
     * @param bearerToken the bearer token
     */
    public JwtAuthenticationToken(String bearerToken) {
        super(null);
        this.bearerToken = bearerToken;
        setAuthenticated(false);
    }

    /**
     * Gets the credentials.
     *
     * @return the credentials
     */
    @Override
    public Object getCredentials() {
        return bearerToken;
    }

    /**
     * Gets the principal.
     *
     * @return the principal
     */
    @Override
    public Object getPrincipal() {
        return "";
    }



}
