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
package org.springframework.security.boot.cas;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CasAuthenticationExtProvider extends CasAuthenticationProvider {

	private static final Log logger = LogFactory.getLog(CasAuthenticationExtProvider.class);
	private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private ServiceProperties serviceProperties;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	private static final String TARGET_PARAMETER_NAME="target";

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER
						.equals(authentication.getPrincipal().toString()) && !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER
						.equals(authentication.getPrincipal().toString()))) {
			// UsernamePasswordAuthenticationToken not CAS related
			return null;
		}

		// If an existing CasAuthenticationToken, just check we created it
		if (authentication instanceof CasAuthenticationToken) {
			if (this.getKey().hashCode() == ((CasAuthenticationToken) authentication)
					.getKeyHash()) {
				return authentication;
			}
			else {
				throw new BadCredentialsException(
						messages.getMessage("CasAuthenticationProvider.incorrectKey",
								"The presented CasAuthenticationToken does not contain the expected key"));
			}
		}

		// Ensure credentials are presented
		if ((authentication.getCredentials() == null)
				|| "".equals(authentication.getCredentials())) {
			throw new BadCredentialsException(messages.getMessage(
					"CasAuthenticationProvider.noServiceTicket",
					"Failed to provide a CAS service ticket to validate"));
		}

		boolean stateless = false;

		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER.equals(authentication
						.getPrincipal())) {
			stateless = true;
		}

		CasAuthenticationToken result = null;

		if (stateless) {
			// Try to obtain from cache
			result = getStatelessTicketCache().getByTicketId(authentication.getCredentials()
					.toString());
		}

		if (result == null) {
			result = this.authenticateNow(authentication);
			result.setDetails(authentication.getDetails());
		}

		if (stateless) {
			// Add to cache
			getStatelessTicketCache().putTicketInCache(result);
		}

		return result;
	}

	private CasAuthenticationToken authenticateNow(final Authentication authentication)
			throws AuthenticationException {
		try {
			final Assertion assertion = this.getTicketValidator().validate(authentication
					.getCredentials().toString(), this.getServiceUrl(authentication));
			final UserDetails userDetails = loadUserByAssertion(assertion);
			userDetailsChecker.check(userDetails);
			return new CasAuthenticationToken(this.getKey(), userDetails,
					authentication.getCredentials(),
					authoritiesMapper.mapAuthorities(userDetails.getAuthorities()),
					userDetails, assertion);
		}
		catch (final TicketValidationException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

	/**
	 * Gets the serviceUrl. If the {@link Authentication#getDetails()} is an instance of
	 * {@link ServiceAuthenticationDetails}, then
	 * {@link ServiceAuthenticationDetails#getServiceUrl()} is used. Otherwise, the
	 * {@link ServiceProperties#getService()} is used.
	 *
	 * @param authentication
	 * @return
	 */
	private String getServiceUrl(Authentication authentication) {
		String serviceUrl;
		if (serviceProperties.getService() == null) {
			throw new IllegalStateException(
					"serviceProperties.getService() cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		}
		else {
			serviceUrl = serviceProperties.getService();
			//动态处理serviceUrl
			ServiceAuthenticationDetails serviceAuthenticationDetails = (ServiceAuthenticationDetails) authentication.getDetails();
			String targetParams = getFieldValue(serviceAuthenticationDetails.getServiceUrl(), TARGET_PARAMETER_NAME);
			if(StringUtils.isNotBlank(targetParams)){
				serviceUrl = CasUrlUtils.addParameter(serviceUrl, TARGET_PARAMETER_NAME, targetParams,false);

			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("serviceUrl = " + serviceUrl);
		}
		return serviceUrl;
	}


	@Override
	public void setServiceProperties(ServiceProperties serviceProperties) {
		super.setServiceProperties(serviceProperties);
		this.serviceProperties = serviceProperties;
	}

	@Override
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		super.setAuthoritiesMapper(authoritiesMapper);
		this.authoritiesMapper = authoritiesMapper;
	}
	/**
	 * 获取字段值
	 *
	 * @param urlStr
	 * @param field
	 * @return
	 */
	private static String getFieldValue(String urlStr, String field) {
		String result = "";
		Pattern pXM = Pattern.compile(field + "=([^&]*)");
		Matcher mXM = pXM.matcher(urlStr);
		while (mXM.find()) {
			result += mXM.group(1);
		}
		return result;
	}

	public static void main(String[] args) {
		String aa = "http://192.168.3.27:30847/apis-authz/authz/login/cas?target=http://192.168.30.71/#/index";
		System.out.println(getFieldValue(aa,"target"));
	}
}
