package com.pamesh.security.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pamesh.security.auth.JwtAuthenticationProvider;
import com.pamesh.security.auth.ResourcePermissonEvaluator;
import com.pamesh.security.auth.RestAccessDeniedHandler;
import com.pamesh.security.auth.RestAuthenticationEntryPoint;
import com.pamesh.security.auth.UserAuthenticationProvider;
import com.pamesh.security.auth.UserAuthenticationSuccessHandler;
import com.pamesh.security.util.JwtUtil;
import com.pamesh.security.web.filter.JwtAuthenticationFilter;
import com.pamesh.security.web.filter.UserAuthenticationFilter;

/**
 * The Class SecurityConfig.
 *
 * @author Pamesh Bansal
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Configure.
     *
     * @param http the http
     * @throws Exception the exception
     */
  //@formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
		.antMatchers("/h2-console/**").permitAll() //Allow for H2-Console
		.anyRequest().authenticated() //All other calls should be authenticated
		.and()
		.addFilterAt(userAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) //Add filter for user login
		.addFilterAfter(jwtFilter().getFilter(), UsernamePasswordAuthenticationFilter.class) //Add JWT Filter
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Stateless session for REST
		.and()
		.exceptionHandling()
			.authenticationEntryPoint(restAuthenticationEntryPoint()) //Entry point
			.accessDeniedHandler(restAccessDeniedHandler()) //Access Denied handler
		.and()
		.csrf().disable();
		
		http.headers().frameOptions().sameOrigin();
	}
	//@formatter:on

    /**
     * Configure.
     *
     * @param auth the auth
     * @throws Exception the exception
     */
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthenticationProvider()).authenticationProvider(userAuthenticationProvider());
    }

    /**
     * User authentication success handler.
     *
     * @return the user authentication success handler
     */
    @Bean
    public UserAuthenticationSuccessHandler userAuthenticationSuccessHandler() {
        return new UserAuthenticationSuccessHandler();
    }

    /**
     * Jwt authentication provider.
     *
     * @return the jwt authentication provider
     */
    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider();
    }

    /**
     * User authentication provider.
     *
     * @return the user authentication provider
     */
    @Bean
    public UserAuthenticationProvider userAuthenticationProvider() {
        return new UserAuthenticationProvider();
    }

    /**
     * Jwt authentication filter.
     *
     * @return the jwt authentication filter
     * @throws Exception the exception
     */
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        List<String> ignorePaths = new ArrayList<>();
        ignorePaths.add("/login");
        ignorePaths.add("/h2-console/**");
        return new JwtAuthenticationFilter(authenticationManager(), ignorePaths);
    }

    /**
     * Jwt filter.
     *
     * @return the filter registration bean
     * @throws Exception the exception
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter() throws Exception {
        final FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(jwtAuthenticationFilter());
        /*
         * Normally the filter is called twice, one invocation is by servlet container and the other is by
         * Spring Security, So by adding this line in the filter bean implementation make sure that it is
         * not registered in servlet. Filter will be added only in spring security calls for token.
         */
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    /**
     * User auth filter.
     *
     * @return the filter registration bean
     * @throws Exception the exception
     */
    @Bean
    public FilterRegistrationBean<UserAuthenticationFilter> userAuthFilter() throws Exception {
        final FilterRegistrationBean<UserAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(userAuthenticationFilter());
        /*
         * Normally the filter is called twice, one invocation is by servlet container and the other is by
         * Spring Security, So by adding this line in the filter bean implementation make sure that it is
         * not registered in servlet. Filter will be added only in spring security calls for token.
         */
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    /**
     * User authentication filter.
     *
     * @return the user authentication filter
     * @throws Exception the exception
     */
    public UserAuthenticationFilter userAuthenticationFilter() throws Exception {
        UserAuthenticationFilter filter = new UserAuthenticationFilter(authenticationManager(), userAuthenticationSuccessHandler(), mapper());
        filter.setAuthenticationFailureHandler(failureHandler(restAuthenticationEntryPoint()));
        return filter;
    }

    /**
     * Mapper.
     *
     * @return the object mapper
     */
    @Bean
    public ObjectMapper mapper() {
        return new ObjectMapper();
    }

    /**
     * Failure handler.
     *
     * @param entryPoint the entry point
     * @return the authentication entry point failure handler
     */
    @Bean
    public AuthenticationEntryPointFailureHandler failureHandler(RestAuthenticationEntryPoint entryPoint) {
        return new AuthenticationEntryPointFailureHandler(restAuthenticationEntryPoint());
    }

    /**
     * Rest authentication entry point.
     *
     * @return the rest authentication entry point
     */

    @Bean
    public RestAuthenticationEntryPoint restAuthenticationEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    /**
     * Rest access denied handler.
     *
     * @return the rest access denied handler
     */
    @Bean
    public RestAccessDeniedHandler restAccessDeniedHandler() {
        return new RestAccessDeniedHandler();
    }

    /**
     * Jwt util.
     *
     * @param loader the loader
     * @return the jwt util
     */
    @Bean
    public JwtUtil jwtUtil(ResourceLoader loader) {
        return new JwtUtil(loader, "classpath:private.pem", "classpath:public.pem");
    }

    /**
     * Password encoder.
     *
     * @return the password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PermissionEvaluator permissonEvaluator() {
        return new ResourcePermissonEvaluator();
    }
}
