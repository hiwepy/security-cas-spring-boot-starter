package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.CollectionUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Implementation of CAS authentication failure handling
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
public class CasProxyFailureRoutingHandler extends ListenedAuthenticationFailureHandler {
	
	private SecurityCasAuthcProperties authcProperties;
	
	/**
	 * Constructs a new cas proxy failure routing handler instance.
	 *
	 * @param authcProperties the authc properties
	 */
	public CasProxyFailureRoutingHandler(SecurityCasAuthcProperties authcProperties) {
		super("");
		this.authcProperties = authcProperties;
	}
	
	/**
	 * Constructs a new cas proxy failure routing handler instance.
	 *
	 * @param authenticationListeners the authentication listeners
	 * @param authcProperties the authc properties
	 */
	public CasProxyFailureRoutingHandler(List<AuthenticationListener> authenticationListeners, SecurityCasAuthcProperties authcProperties) {
		super(authenticationListeners, "");
		this.authcProperties = authcProperties;
	}

	@Override
    /**
     * <p>Sets the default failure url.</p>
     * @param defaultFailureUrl
     */
	public void setDefaultFailureUrl(String defaultFailureUrl) {
		// do nothing
	}

	/**
	 * on Authentication Failure.
	 *
	 * @param request the request
	 * @param response the response
	 * @param exception the exception
	 * @throws IOException if an error occurs
	 * @throws ServletException if an error occurs
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		if(!CollectionUtils.isEmpty(getAuthenticationListeners())){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				try {
					authenticationListener.onFailure(request, response, exception);
				} catch (Exception e) {
					log.error("AuthenticationListener : {} error : {}", authenticationListener, e.getMessage());
				}
			}
		}

		log.error("Cas Proxy Failure, error : {}", exception);

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

	}

}
