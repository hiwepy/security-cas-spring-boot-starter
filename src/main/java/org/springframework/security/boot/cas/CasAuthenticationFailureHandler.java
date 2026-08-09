package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.core.AuthenticationException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Implementation of CAS authentication failure handling
 */
@Slf4j
public class CasAuthenticationFailureHandler extends ListenedAuthenticationFailureHandler {

	private SecurityCasAuthcProperties authcProperties;

	public CasAuthenticationFailureHandler(SecurityCasAuthcProperties authcProperties) {
		super("/");
		this.authcProperties = authcProperties;
	}

	public CasAuthenticationFailureHandler(List<AuthenticationListener> authenticationListeners,
										   SecurityCasAuthcProperties authcProperties) {
		super(authenticationListeners, "/");
		this.authcProperties = authcProperties;
	}

	@Override
	public void setDefaultFailureUrl(String defaultFailureUrl) {
		// do nothing
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		log.error("Cas Authentication Failure, error : {}", exception);

		// 1. Retrieve the matching CasServerProperties for the request
		SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
		// 2. Determine whether to always use the default failure URL
		if (serverProperties.isAlwaysUseDefaultFailureUrl()) {
			log.debug("Always Use Default Failure Url : {}", serverProperties.getDefaultFailureUrl());
			if (serverProperties.getDefaultFailureUrl() == null) {
				log.debug("No failure URL set, sending 401 Unauthorized error");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			}
			else {
				saveException(request, exception);
				if (serverProperties.isForwardToDestination()) {
					log.debug("Forwarding to " + serverProperties.getDefaultFailureUrl());
					request.getRequestDispatcher(serverProperties.getDefaultFailureUrl()).forward(request, response);
				}
				else {
					log.debug("Redirecting to " + serverProperties.getDefaultFailureUrl());
					getRedirectStrategy().sendRedirect(request, response, serverProperties.getDefaultFailureUrl());
				}
			}
		}

		if(exception instanceof BadCredentialsException) {
			String redirectUrl = CasUrlUtils.constructRedirectUrl(request, serverProperties);
			log.debug("Cas Authentication Failure, redirectUrl : {}", redirectUrl);
			getRedirectStrategy().sendRedirect(request, response, redirectUrl);
			return;
		}

		String redirectUrl = CasUrlUtils.constructFailureRedirectUrl(serverProperties);
		log.debug("Cas Authentication Failure, redirectUrl : {}", redirectUrl);
		getRedirectStrategy().sendRedirect(request, response, redirectUrl);

	}


}
