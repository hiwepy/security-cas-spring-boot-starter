package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.biz.ListenedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Cas认证请求成功后的处理实现
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Slf4j
public class CasAuthenticationSuccessHandler extends ListenedAuthenticationSuccessHandler {

	private SecurityCasAuthcProperties authcProperties;
	private JwtPayloadRepository jwtPayloadRepository;

	public CasAuthenticationSuccessHandler(SecurityCasAuthcProperties authcProperties) {
		super("/");
		this.authcProperties = authcProperties;
	}

	public CasAuthenticationSuccessHandler(List<AuthenticationListener> authenticationListeners, SecurityCasAuthcProperties authcProperties) {
		super(authenticationListeners, "/");
		this.authcProperties = authcProperties;
	}

	@Override
	public void setDefaultTargetUrl(String defaultTargetUrl) {
		// do nothing
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

		log.debug(authentication.getName());

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

		// get target Url
		String targetUrl = determineTargetUrl(request, response, authentication);

		if (response.isCommitted()) {
			log.debug("Response has already been committed. Unable to redirect to "
					+ targetUrl);
			return;
		}
		// 签发jwt
		String tokenString = getJwtPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication);
		// 地址添加token参数
		targetUrl = CasUrlUtils.addParameter(targetUrl, "token", tokenString,true);
		// 地址添加sessionid参数 ,前端统一会话用
		String jsessionid = request.getSession(false).getId();
		targetUrl = CasUrlUtils.addParameter(targetUrl, "jsessionid", jsessionid,true);

		log.debug("token : " + tokenString);
		log.debug("jsessionid :" + jsessionid);
		log.debug("redirect :" + targetUrl);

		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	@Override
	protected String determineTargetUrl(HttpServletRequest request,
										HttpServletResponse response) {
		// 1. 获取请求匹配的CasServerProperties
		SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
		if (serverProperties.isAlwaysUseDefaultTargetUrl()) {
			return serverProperties.getDefaultTargetUrl();
		}

		// Check for the parameter and use that if available
		String targetUrl = null;

		if (serverProperties.getTargetUrlParameter() != null) {
			targetUrl = request.getParameter(serverProperties.getTargetUrlParameter());

			if (StringUtils.hasText(targetUrl)) {
				logger.debug("Found targetUrlParameter in request: " + targetUrl);

				return targetUrl;
			}
		}

		if (serverProperties.isUseReferer() && !StringUtils.hasLength(targetUrl)) {
			targetUrl = request.getHeader(HttpHeaders.REFERER);
			logger.debug("Using Referer header: " + targetUrl);
		}

		if (!StringUtils.hasText(targetUrl)) {
			targetUrl = serverProperties.getDefaultTargetUrl();
			logger.debug("Using default Url: " + targetUrl);
		}

		return targetUrl;
	}

	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}

}
