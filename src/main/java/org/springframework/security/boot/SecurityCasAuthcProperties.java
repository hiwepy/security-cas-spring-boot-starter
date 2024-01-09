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

	/**
	 * CAS protocol.
	 */
	public enum CasProtocol {
		CAS10, CAS20, CAS20_PROXY, CAS30, CAS30_PROXY, SAML
	}

	/** Authorization Path Pattern */
	private String pathPattern = "/login/cas";

	/**
	 * Defaults to true
	 */
	private boolean eagerlyCreateSessions = true;

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
				if (tag.equals(server.getName())) {
					return server;
				}
			}
		}
		String referer = request.getHeader(HttpHeaders.REFERER);
		if (StringUtils.hasText(referer)) {
			for (SecurityCasServerProperties server : this.servers) {
				if (referer.startsWith(server.getReferer())) {
					return server;
				}
			}
		}
		return CollectionUtils.firstElement(this.servers);
	}
	
}
