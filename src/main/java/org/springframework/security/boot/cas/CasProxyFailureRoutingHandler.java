package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.CollectionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Cas认证请求失败后的处理实现
 */
@Slf4j
public class CasProxyFailureRoutingHandler extends ListenedAuthenticationFailureHandler {
	
	private SecurityCasAuthcProperties authcProperties;
	
	public CasProxyFailureRoutingHandler(SecurityCasAuthcProperties authcProperties) {
		super("");
		this.authcProperties = authcProperties;
	}
	
	public CasProxyFailureRoutingHandler(List<AuthenticationListener> authenticationListeners, SecurityCasAuthcProperties authcProperties) {
		super(authenticationListeners, "");
		this.authcProperties = authcProperties;
	}
	
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

		// 1. 获取请求匹配的CasServerProperties
		SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
		// 2. 判断是否存总是使用默认的失败地址
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
