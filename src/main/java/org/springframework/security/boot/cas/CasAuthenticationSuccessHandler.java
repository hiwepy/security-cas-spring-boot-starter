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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * Implementation of CAS authentication success handling
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
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
    /**
     * <p>Sets the default target url.</p>
     * @param defaultTargetUrl
     */
	public void setDefaultTargetUrl(String defaultTargetUrl) {
		// do nothing
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		//CasAuthenticationToken casToken = (CasAuthenticationToken) authentication;

		//Assertion assertion = casToken.getAssertion();
		/*
		 * Retrieve the unique identifier of the user 由UIA的配置不同可分为两种： (1)学生：学号；教工：身份证号 (2)学生：学号；教工：教工号
		 */
		//String ssoid = assertion.getPrincipal().getName();
		/*
		 * Retrieve extended user information 扩展信息由UIA的SSO配置决定 其中，由于用户可能拥有多个角色，岗位，部门等
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
		// Issue JWT token
		String tokenString = getJwtPayloadRepository().issueJwt((AbstractAuthenticationToken) authentication);
		// Append token parameter to URL
		targetUrl = CasUrlUtils.addParameter(targetUrl, "token", tokenString,true);
		// Append session ID parameter to URL ,前端统一会话用
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
		// 1. Retrieve the matching CasServerProperties for the request
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

    /**
     * <p>Returns the jwt payload repository.</p>
     * @return the get jwt payload repository
     */
	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

    /**
     * <p>Sets the jwt payload repository.</p>
     * @param jwtPayloadRepository
     */
	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}

}
