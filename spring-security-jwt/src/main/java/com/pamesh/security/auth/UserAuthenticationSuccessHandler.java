package com.pamesh.security.auth;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import com.pamesh.security.util.JwtUtil;

/**
 * The Class UserAuthenticationSuccessHandler.
 *
 * @author Pamesh Bansal
 */
public class UserAuthenticationSuccessHandler implements AuthenticationSuccessHandler {


    @Autowired
    private JwtUtil jwtUtil;

    /**
     * On authentication success.
     *
     * @param request the request
     * @param response the response
     * @param authentication the authentication
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws ServletException the servlet exception
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        String jwt = jwtUtil.generateJWT(token.getName(), token.getAuthorities());
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
    }

}
