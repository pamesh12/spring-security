package com.pamesh.security.auth;

import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.CollectionUtils;
import com.pamesh.security.model.RoleModel;
import com.pamesh.security.model.UserModel;
import com.pamesh.security.service.UserService;

/**
 * The Class UserAuthenticationProvider.
 *
 * @author Pamesh Bansal
 */
public class UserAuthenticationProvider implements AuthenticationProvider {

    /** The Constant LOGGER. */
    private static final Logger LOGGER = LoggerFactory.getLogger(UserAuthenticationProvider.class);

    /** The user service. */
    @Autowired
    private UserService userService;

    /** The password encoder. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Authenticate.
     *
     * @param authentication the authentication
     * @return the authentication
     * @throws AuthenticationException the authentication exception
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserModel userModel = userService.fetchUser(authentication.getPrincipal().toString());

        if (userModel == null) {
            throw new BadCredentialsException("Credentials Invalid");
        }

        if (!passwordEncoder.matches(authentication.getCredentials().toString(), userModel.getPassword())) {
            throw new BadCredentialsException("Credentials Invalid");
        }

        Set<RoleModel> roles = userModel.getRoles();

        if (CollectionUtils.isEmpty(roles)) {
            throw new BadCredentialsException("User roles not found");
        }

        String[] roleList = roles.stream().map(e -> e.getName()).toArray(String[]::new);
        List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(roleList);

        LOGGER.info("User Model {}", userModel);
        return new UsernamePasswordAuthenticationToken(userModel.getUserId(), "", authorities);
    }

    /**
     * Supports.
     *
     * @param authentication the authentication
     * @return true, if successful
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
