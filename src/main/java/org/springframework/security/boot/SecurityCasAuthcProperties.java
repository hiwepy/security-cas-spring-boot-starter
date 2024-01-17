package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCorsProperties;
import org.springframework.security.boot.biz.property.SecurityHeaderCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityHeadersProperties;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(SecurityCasAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityCasAuthcProperties extends SecurityAuthcProperties {

	/**
	 * Default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
	 */
	public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";

	public static final String DEFAULT_CAS_SERVICE_TAG_PARAMETER = "tag";
	/**
	 * Default timeout in milliseconds.
	 */
	public static final long DEFAULT_TIMEOUT = 60000;

	public static final String PREFIX = "spring.security.cas.authc";

	/** Authorization Path Pattern */
	private String pathPattern = "/cas/**";

	/** Cas Authorization Path Pattern */
	private String pathCasPattern = "/cas/login";

	/** Saml Authorization Path Pattern */
	private String pathSaml11Pattern = "/cas/login-saml11";

	/**
	 * Defaults to true
	 */
	private boolean eagerlyCreateSessions = true;

	/**
	 * Specifies whether any proxy is OK. Defaults to false.
	 */
	private boolean acceptAnyProxy = false;

	/**
	 * The URL to watch for PGTIOU/PGT responses from the CAS server. Should be
	 * defined from the root of the context. For example, if your application is
	 * deployed in /cas-client-app and you want the proxy receptor URL to be
	 * /cas-client-app/my/receptor you need to configure proxyReceptorUrl to be
	 * /my/receptor.
	 */
	private String proxyReceptorUrl = "/login/cas-proxy";

	/**
	 * The callback URL to provide the CAS server to accept Proxy Granting Tickets. i.e. /proxyCallback
	 */
	private String proxyCallbackUrl;



	@NestedConfigurationProperty
	private SecurityHeaderCorsProperties cors = new SecurityHeaderCorsProperties();
	
	@NestedConfigurationProperty
	private SecurityHeaderCsrfProperties csrf = new SecurityHeaderCsrfProperties();
	
	@NestedConfigurationProperty
	private SecurityHeadersProperties headers = new SecurityHeadersProperties();

	/**
	 * Specifies the name of the request parameter on where to find the Server (i.e. tag).
	 */
	private String serverTagParameterName = DEFAULT_CAS_SERVICE_TAG_PARAMETER;

	@NestedConfigurationProperty
	private List<SecurityCasServerProperties> servers = new ArrayList<>();

	public SecurityCasServerProperties getByRequest(HttpServletRequest request) {
		if (CollectionUtils.isEmpty(this.servers)) {
			throw new IllegalArgumentException("servers must not be empty");
		}
		String tag = request.getParameter(this.serverTagParameterName);
		if (StringUtils.hasText(tag)) {
			for (SecurityCasServerProperties server : this.servers) {
				if (tag.equals(server.getServerTag())) {
					return server;
				}
			}
		}
		String referer = request.getHeader(HttpHeaders.REFERER);
		if (StringUtils.hasText(referer)) {
			for (SecurityCasServerProperties server : this.servers) {
				if (referer.startsWith(server.getServiceReferer())) {
					return server;
				}
			}
		}
		return CollectionUtils.firstElement(this.servers);
	}
	
}
