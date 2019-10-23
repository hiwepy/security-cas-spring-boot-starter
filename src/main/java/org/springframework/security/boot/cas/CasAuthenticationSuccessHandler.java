package org.springframework.security.boot.cas;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.core.Authentication;

/**
 * Cas认证请求成功后的处理实现
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class CasAuthenticationSuccessHandler extends ListenedAuthenticationSuccessHandler {
	
	private Logger logger = LoggerFactory.getLogger(CasAuthenticationSuccessHandler.class);
	private SecurityCasAuthcProperties authcProperties;
	
	public CasAuthenticationSuccessHandler(SecurityCasAuthcProperties authcProperties) {
		super(authcProperties.getLoginUrl());
		this.authcProperties = authcProperties;
	}
	
	public CasAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, SecurityCasAuthcProperties authcProperties) {
		super(authenticationListeners, authcProperties.getLoginUrl());
		this.authcProperties = authcProperties;
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		//调用事件监听器
		if(getAuthenticationListeners() != null && getAuthenticationListeners().size() > 0){
			for (AuthenticationListener authenticationListener : getAuthenticationListeners()) {
				authenticationListener.onSuccess(request, response, authentication);
			}
		}
		
		logger.error("Success");
		
		String redirectUrl = CasUrlUtils.constructLoginRedirectUrl(authcProperties);
		
		logger.debug(authentication.getName());
		logger.debug(redirectUrl);
		
		//super.onAuthenticationSuccess(request, response, authentication);

	}

}
