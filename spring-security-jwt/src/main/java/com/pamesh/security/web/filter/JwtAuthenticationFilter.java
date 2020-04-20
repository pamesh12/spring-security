package com.pamesh.security.web.filter;

import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import com.pamesh.security.auth.JwtAuthenticationToken;

/**
 * The Class JwtAuthenticationFilter.
 *
 * @author Pamesh Bansal
 */
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {


    private final List<String> ignorePaths;

    /**
     * Instantiates a new jwt authentication filter.
     *
     * @param authenticationManager the authentication manager
     */
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, List<String> ignorePaths) {
        super("/**");
        this.ignorePaths = ignorePaths;
        setAuthenticationManager(authenticationManager);
    }

    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (ignorePaths != null) {
            for (String path : ignorePaths) {
                RequestMatcher matcher = new AntPathRequestMatcher(path);
                boolean result = matcher.matches(request);
                if (result) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Attempt authentication.
     *
     * @param request the request
     * @param response the response
     * @return the authentication
     * @throws AuthenticationException the authentication exception
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws ServletException the servlet exception
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String jwtBearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(jwtBearerToken)) {
            JwtAuthenticationToken token = JwtAuthenticationToken.builder().bearerToken(jwtBearerToken).build();
            return getAuthenticationManager().authenticate(token);
        } else {
            logger.error("Authorization Header missing from request");
            throw new AuthenticationCredentialsNotFoundException("Authorization Header missing from request");
        }
    }

    /**
     * Successful authentication.
     *
     * @param request the request
     * @param response the response
     * @param chain the chain
     * @param authResult the auth result
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws ServletException the servlet exception
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        //super.successfulAuthentication(request, response, chain, authResult);
        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(request, response);
    }

}
