package com.pamesh.security.auth;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * The Class RestAuthenticationEntryPoint.
 *
 * @author Pamesh Bansal
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint{

	/**
	 * Commence.
	 *
	 * @param request the request
	 * @param response the response
	 * @param authException the auth exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws ServletException the servlet exception
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		//response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
	}

}
