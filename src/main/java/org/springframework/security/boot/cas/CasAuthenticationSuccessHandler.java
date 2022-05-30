package org.springframework.security.boot.cas;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.core.Authentication;

/**
 * Cas认证请求成功后的处理实现
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class CasAuthenticationSuccessHandler extends ListenedAuthenticationSuccessHandler {
	
	private Logger logger = LoggerFactory.getLogger(CasAuthenticationSuccessHandler.class);
	private SecurityCasAuthcProperties authcProperties;
	private JwtPayloadRepository jwtPayloadRepository;
	 
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
	 
		//CasAuthenticationToken casToken = (CasAuthenticationToken) authentication;
		
		//Assertion assertion = casToken.getAssertion();
		/*
		 * 获取用户的唯一标识信息 由UIA的配置不同可分为两种： (1)学生：学号；教工：身份证号 (2)学生：学号；教工：教工号
		 */
		//String ssoid = assertion.getPrincipal().getName();
		/*
		 * 获取用户扩展信息 扩展信息由UIA的SSO配置决定 其中，由于用户可能拥有多个角色，岗位，部门等
		Map<String, Object> attributes = assertion.getPrincipal().getAttributes();
		*/
		
		logger.debug(authentication.getName());
		
		super.onAuthenticationSuccess(request, response, authentication);

	}
	
	/**
	 * Invokes the configured {@code RedirectStrategy} with the URL returned by the
	 * {@code determineTargetUrl} method.
	 * <p>
	 * The redirect will not be performed if the response has already been committed.
	 */
	@Override
	protected void handle(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		
		// 前端跳转代理
		if(authcProperties.isFrontendProxy()) {
			
			// 签发jwt
	    	String tokenString = getJwtPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication);
			// 重定向
	        String targetUrl = CasUrlUtils.addParameter(authcProperties.getFrontendTargetUrl(), "token", tokenString);
	        	   targetUrl = CasUrlUtils.addParameter(targetUrl, getTargetUrlParameter(), determineTargetUrl(request, response));
	       String jsessionid = request.getSession(false).getId();
			//返回sessionid ,前端统一会话用
			targetUrl = CasUrlUtils.addParameter(targetUrl, "jsessionid", jsessionid);
			logger.debug("jsessionid :" + jsessionid);
	        logger.debug("redirect :" + targetUrl);
	        logger.debug("token : " + tokenString);
	        	   
			if (response.isCommitted()) {
				logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
				return;
			}
			response.sendRedirect(targetUrl);
			//getRedirectStrategy().sendRedirect(request, response, targetUrl);
			
		} else {
			super.handle(request, response, authentication);
		}
	}

	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}
	
}
