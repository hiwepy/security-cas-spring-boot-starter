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
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.lang.NonNull;
import org.springframework.security.cas.ServiceProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
	 * CAS Validation Type.
	 */
	public enum ValidationType {

		CAS10(Protocol.CAS1),
		CAS20(Protocol.CAS2),
		CAS20_PROXY(Protocol.CAS2),
		CAS30(Protocol.CAS3),
		CAS30_PROXY(Protocol.CAS3),
		SAML(Protocol.SAML11);

		Protocol protocol;

		ValidationType(Protocol protocol) {
			this.protocol = protocol;
		}

		public Protocol getProtocol() {
			return protocol;
		}

	}

	/**
	 * CAS Validation Response.
	 */
	public enum ValidationResponse {
		JSON, XML
	}

	/**
	 * Whether Enable This Cas Server.
	 */
	private boolean enabled = true;
	/**
	 * CAS server Match Tag. Required.
	 */
	private String serverTag;
	/**
	 * CAS server Match Referer. Required.
	 */
	private String referer;

	private String defaultTargetUrl = "/";

	private boolean alwaysUseDefaultTargetUrl = false;

	private boolean useReferer = false;

	private boolean alwaysUseDefaultFailureUrl = false;
	private String defaultFailureUrl;
	private boolean forwardToDestination = false;
	private boolean allowSessionCreation = true;


	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	private String targetUrlParameter = "target";
	/**
	 * CAS server URL E.g. https://example.com/cas or https://cas.example. Required.
	 */
	private String serverUrlPrefix;
	/**
	 * CAS server login URL E.g. https://example.com/cas/login or https://cas.example/login. Required.
	 */
	private String serverLoginUrl;
	/**
	 * CAS server logout URL E.g. https://example.com/cas/logout or https://cas.example/logout. Required.
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
	 * Converts the returned attribute values to uppercase values.
	 * true if it should convert, false otherwise.
	 */
	private boolean attributeConvertToUpperCase = false;
	/**
	 * Name of attributes to fetch from assertion to use when populating spring security context.
	 */
	private List<String> attributeAuthorities = new ArrayList<>();

	/**
	 * If true, then any non-null artifact (ticket) should be authenticated.
	 * Additionally, the service will be determined dynamically in order to ensure
	 * the service matches the expected value for this artifact.
	 */
	private boolean authenticateAllArtifacts = false;
	/**
	 * Specifies whether the artifact should be sent using the artifact parameter or
	 */
	private boolean artifactParameterOverPost = false;
	/**
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
	 * Specifies whether gateway=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all)
	 */
	private Boolean gateway = Boolean.FALSE;
	/**
	 * Parameter name that stores logout request for SLO
	 */
	private String logoutParameterName = ConfigurationKeys.LOGOUT_PARAMETER_NAME.getDefaultValue();
	/**
	 * The logout callback path configured at the CAS server, if there is one
	 */
	private String logoutCallbackPath;
	/**
	 * Specifies the proxy chain.
	 * Each acceptable proxy chain should include a space-separated list of URLs (for exact match) or regular expressions of URLs (starting by the ^ character).
	 * Each acceptable proxy chain should appear on its own line.
	 */
	private String allowedProxyChains;
	/**
	 * Specifies whether renew=true should be sent to the CAS server. Valid values
	 * are either true/false (or no value at all). Note that renew cannot be
	 * specified as local init-param setting..
	 */
	private Boolean renew = Boolean.FALSE;
	/**
	 * Parameter name that stores the state of the CAS server webflow for the callback
	 */
	private String relayStateParameterName = ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getDefaultValue();
	/**
	 * CAS-protected client application host URL E.g. https://myclient.example.com Required.
	 */
	private String serviceHostUrl;
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
	 */
	private String serviceUrl;
	/**
	 * Whether to store the Assertion in session or not. If sessions are not used,
	 * tickets will be required for each request. Defaults to true.
	 */
	private boolean useSession = true;
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
	private long ticketTimeout = DEFAULT_TIMEOUT;
	/**
	 * ValidationType the CAS protocol validation type. Defaults to CAS3 if not explicitly set.
	 */
	private ValidationType validationType = ValidationType.CAS30;

	private ValidationResponse validationResponse = ValidationResponse.XML;

	/**
	 * Specify whether the filter should redirect the user agent after a
	 * successful validation to remove the ticket parameter from the query
	 * string.
	 */
	private boolean redirectAfterValidation = true;

	/** Determines whether an exception is thrown when there is a ticket validation failure. */
	private boolean exceptionOnValidationFailure = false;

	private int millisBetweenCleanUps = 60000;

	private SingleLogout singleLogout;

	public static class SingleLogout{
		/**
		 * whether to receive the single logout request from cas server.
		 */
		private boolean enabled = false;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}
	}
	
}
