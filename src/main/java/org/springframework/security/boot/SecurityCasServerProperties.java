/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.web.cors.CorsConfiguration;

import java.util.HashMap;
import java.util.Map;

/**
 * Security Cas Server Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityCasServerProperties {

	/**
	 * Default timeout in milliseconds.
	 */
	public static final long DEFAULT_TIMEOUT = 60000;

	/**
	 * Whether Enable This Cas Server.
	 */
	private boolean enabled = true;
	/**
	 * CAS server Match Tag Name. Required.
	 */
	private String name;
	/**
	 * CAS server Match Referer. Required.
	 */
	private String referer;
	/**
	 * CAS server URL E.g. https://example.com/cas or https://cas.example. Required.
	 */
	private String serverUrlPrefix;
	/**
	 * CAS server login URL E.g. https://example.com/cas/login or https://cas.example/login. Required.
	 */
	private String serverLoginUrl;
	/**
	 * The location of the CAS server logout URL, i.e. https://localhost:8443/cas/logout
	 */
	private String serverLogoutUrl;
	/**
	 * The url where the application is redirected if the CAS service ticket validation failed (example : /mycontextpatch/cas_error.jsp)
	 */
	private String failureUrl;
	/**
	 *  The Map of key/value pairs associated with this principal.
	 */
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
	 * Whether Enable Front-end Authorization Proxy.
	 */
	private boolean frontendProxy = false;

	private String frontendTargetUrl = "/";

	/**
	 * Specifies whether gateway=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all)
	 */
	private Boolean gateway = Boolean.FALSE;

	/** Parameter name that stores logout request for SLO */
	private String logoutParameterName = ConfigurationKeys.LOGOUT_PARAMETER_NAME.getDefaultValue();

	/** The logout callback path configured at the CAS server, if there is one */
	private String logoutCallbackPath;

	private boolean ignoreInitConfiguration = true;

	/** The protocol of the CAS Client. */
	private SecurityCasAuthcProperties.CasProtocol protocol = SecurityCasAuthcProperties.CasProtocol.CAS20;

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

	/**
	 * Specifies whether renew=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all). Note that renew cannot be
	 * specified as local init-param setting..
	 */
	private Boolean renew = Boolean.FALSE;


	/** Parameter name that stores the state of the CAS server webflow for the callback */
	private String relayStateParameterName = ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getDefaultValue();


	/**
	 * Represents the service the user is authenticating to.
	 * <p>
	 * This service is the callback URL belonging to the local Spring Security System for
	 * Spring secured application. For example,
	 *
	 * <pre>
	 * https://www.mycompany.com/application/login/cas
	 * </pre>
	 *
	 * The URL of the service the user is authenticating to
	 *
	 */
	private String serviceUrl;

	/**
	 * Specifies the name of the request parameter on where to find the service
	 * (i.e. service).
	 */
	private String serviceParameterName = ServiceProperties.DEFAULT_CAS_SERVICE_PARAMETER;

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
	
}