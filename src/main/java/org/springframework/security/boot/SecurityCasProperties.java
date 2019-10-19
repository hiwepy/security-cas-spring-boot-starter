package org.springframework.security.boot;

import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.cas.ServiceProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityCasProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityCasProperties {

	/**
	 * Default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
	 */
	public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
	/**
	 * Default timeout in milliseconds.
	 */
	public static final long DEFAULT_TIMEOUT = 60000;

	public static final String PREFIX = "spring.security.cas";

	/**
	 * CAS protocol.
	 */
	public static enum CasProtocol {
		CAS10, CAS20, CAS20_PROXY, CAS30, CAS30_PROXY, SAML
	}

	/** Whether Enable Cas. */
	private boolean enabled = false;

	/**
	 * Defines the location of the CAS server login URL, i.e. https://localhost:8443/cas/login
	 */
	private String loginUrl;
	/**
	 * Defines the location of the CAS server logout URL, i.e. https://localhost:8443/cas/logout
	 */
	private String logoutUrl;
	/**
	 * Defines the location of the CAS server rest URL, i.e. https://localhost:8443/cas/v1/tickets
	 */
	private String restUrl;
	/** 
	 * The prefix url of the CAS server. i.e.https://localhost:8443/cas 
	 */
	private String prefixUrl;
	/** 
	 * The url where the application is redirected if the CAS service ticket validation failed (example : /mycontextpatch/cas_error.jsp) 
	 */
	private String failureUrl;

	private String[] attributes = new String[] {};

	/**
	 * Specifies the name of the request parameter on where to find the artifact (i.e. ticket).
	 */
	private String artifactParameterName = ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER;
	/**
	 * If true, then any non-null artifact (ticket) should be authenticated.
	 * Additionally, the service will be determined dynamically in order to ensure
	 * the service matches the expected value for this artifact.
	 */
	private boolean authenticateAllArtifacts = false;

	private boolean artifactParameterOverPost = false;
	
	/** 
     * Specifies whether any proxy is OK. Defaults to false. 
     */
	private boolean acceptAnyProxy = false;
	/**
	 * Specifies the proxy chain. 
	 * Each acceptable proxy chain should include a space-separated list of URLs (for exact match) or regular expressions of URLs (starting by the ^ character). 
	 * Each acceptable proxy chain should appear on its own line.
	 */
	private String allowedProxyChains;
	/* 
	 * Map containing user defined parameters 
	 */
	private Map<String, String> customParams = new HashMap<>();
	/** 
	 * Specifies the encoding charset the client should use 
	 */
	private String encoding = "UTF-8";
	/** 
	 * Whether the client should auto encode the service url. Defaults to true 
	 */
	private boolean encodeServiceUrl = true;
	/**
	 * Determines whether the Service URL should include the session id for the
	 * specific user. As of CAS 3.0.5, the session id will automatically be
	 * stripped. However, older versions of CAS (i.e. CAS 2), do not automatically
	 * strip the session identifier (this is a bug on the part of the older server
	 * implementations), so an option to disable the session encoding is provided
	 * for backwards compatibility.
	 *
	 * By default, encoding is enabled.
	 */
	private boolean encodeServiceUrlWithSessionId = true;
	/** 
	 * Defaults to true 
	 */
	private boolean eagerlyCreateSessions = true;
	
	/**
	 * Specifies whether gateway=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all)
	 */
	private boolean gateway = false;

	private boolean ignoreInitConfiguration = false;
	/** Defaults to logoutRequest */
	private String logoutParameterName;
	/** The protocol of the CAS Client. */
	private CasProtocol protocol = CasProtocol.CAS20;
	/**
	 * The callback URL to provide the CAS server to accept Proxy Granting Tickets.
	 */
	private String proxyCallbackUrl;
	/**
	 * The URL to watch for PGTIOU/PGT responses from the CAS server. Should be
	 * defined from the root of the context. For example, if your application is
	 * deployed in /cas-client-app and you want the proxy receptor URL to be
	 * /cas-client-app/my/receptor you need to configure proxyReceptorUrl to be
	 * /my/receptor.
	 */
	private String proxyReceptorUrl;
	/**
	 * Specifies whether renew=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all). Note that renew cannot be
	 * specified as local init-param setting..
	 */
	private boolean renew = false;
	/** Name of parameter containing the state of the CAS server webflow. */
	private String relayStateParameterName = ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getDefaultValue();
	/**
	 * The service URL to send to the CAS server, i.e.
	 * https://localhost:8443/yourwebapp/index.html
	 */
	private String service;
	/**
	 * Specifies the name of the request parameter on where to find the service
	 * (i.e. service).
	 */
	private String serviceParameterName = ServiceProperties.DEFAULT_CAS_SERVICE_PARAMETER;
	/** Defines the location of the application cas callback URL, i.e. /callback */
	private String serviceCallbackUrl;
	/**
	 * A reference to a properties file that includes SSL settings for client-side
	 * SSL config, used during back-channel calls. The configuration includes keys
	 * for protocol which defaults to SSL,keyStoreType, keyStorePath,
	 * keyStorePass,keyManagerType which defaults to SunX509 andcertificatePassword.
	 */
	private String sslConfigFile;
	/**
	 * The tolerance for drifting clocks when validating SAML tickets. Note that 10
	 * seconds should be more than enough for most environments that have NTP time
	 * synchronization. Defaults to 1000 msec
	 */
	private long tolerance = 5000L;
	/**
	 * time, in milliseconds, before a {@link ProxyGrantingTicketHolder} is
	 * considered expired and ready for removal.
	 * 
	 * @see ProxyGrantingTicketStorageImpl#DEFAULT_TIMEOUT
	 */
	private long timeout = DEFAULT_TIMEOUT;
	/**
	 * Whether to store the Assertion in session or not. If sessions are not used,
	 * tickets will be required for each request. Defaults to true.
	 */
	private boolean useSession = true;

	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();

}
