package com.pamesh.security.web.filter;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pamesh.security.vo.User;

/**
 * The Class UserAuthenticationFilter.
 *
 * @author Pamesh Bansal
 */
public class UserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /** The mapper. */
    private ObjectMapper mapper;

    /**
     * Instantiates a new user authentication filter.
     *
     * @param authenticationManager the authentication manager
     * @param successHandler the success handler
     */
    public UserAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationSuccessHandler successHandler, ObjectMapper mapper) {
        super();
        setAuthenticationManager(authenticationManager);
        setAuthenticationSuccessHandler(successHandler);
        this.mapper = mapper;
    }

    /**
     * Attempt authentication.
     *
     * @param request the request
     * @param response the response
     * @return the authentication
     * @throws AuthenticationException the authentication exception
     */
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        User creds = null;
        try {
            creds = mapper.readValue(request.getInputStream(), User.class);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Authentication request not valid: " + e.getMessage());
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(creds.getUserName(), creds.getPassword());

        return this.getAuthenticationManager().authenticate(authRequest);
    }

}
