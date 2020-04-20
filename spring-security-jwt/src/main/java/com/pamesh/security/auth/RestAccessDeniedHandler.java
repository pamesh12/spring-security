package com.pamesh.security.auth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * The Class RestAccessDeniedHandler.
 *
 * @author Pamesh Bansal
 */
public class RestAccessDeniedHandler implements AccessDeniedHandler {

	/**
	 * Handle.
	 *
	 * @param request the request
	 * @param response the response
	 * @param accessDeniedException the access denied exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws ServletException the servlet exception
	 */
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
	}

}
