package com.pamesh.security.auth;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import com.pamesh.security.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.lang.Assert;

/**
 * The Class JwtAuthenticationProvider.
 *
 * @author Pamesh Bansal
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Authenticate.
     *
     * @param authentication the authentication
     * @return the authentication
     * @throws AuthenticationException the authentication exception
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication.getCredentials());
        String header = authentication.getCredentials().toString();
        String token = header.substring(7);
        Claims jwt = jwtUtil.parseJWT(token);
        if(jwt != null) {
            List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(String.valueOf(jwt.get("roles")));
            return new UsernamePasswordAuthenticationToken(jwt.getSubject(), "", authorities);
        }
        return null;
    }

    /**
     * Supports.
     *
     * @param authentication the authentication
     * @return true, if successful
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
