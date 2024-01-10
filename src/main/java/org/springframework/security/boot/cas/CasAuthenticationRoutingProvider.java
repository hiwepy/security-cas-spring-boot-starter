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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.WebUtils;
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
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class CasAuthenticationRoutingProvider extends CasAuthenticationProvider {

	private static final Log logger = LogFactory.getLog(CasAuthenticationRoutingProvider.class);
	private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private SecurityCasAuthcProperties authcProperties;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	private static final String TARGET_PARAMETER_NAME = "target";

	public CasAuthenticationRoutingProvider(SecurityCasAuthcProperties authcProperties) {
		this.authcProperties = authcProperties;
	}

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

	protected CasAuthenticationToken authenticateNow(final Authentication authentication)
			throws AuthenticationException {
		try {
			final Assertion assertion = this.getTicketValidator(authentication).validate(authentication
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

	protected TicketValidator getTicketValidator(final Authentication authentication) {
		String targetUrl = getServiceUrl(authentication);

		return super.getTicketValidator();
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

		// 1. 根据referer获取TicketValidator
		HttpServletRequest request = WebUtils.getHttpServletRequest();
		Assert.isTrue(request != null, "request cannot be null");

		// 1. 获取请求匹配的CasServerProperties
		SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);

		String serviceUrl;
		if (serverProperties.getServiceUrl() == null) {
			throw new IllegalStateException(
					"serviceProperties.getService() cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		}
		else {
			serviceUrl = serverProperties.getServiceUrl();
			// 动态处理 serviceUrl
			ServiceAuthenticationDetails serviceAuthenticationDetails = (ServiceAuthenticationDetails) authentication.getDetails();
			String targetParams = CasUrlUtils.getFieldValue(serviceAuthenticationDetails.getServiceUrl(), TARGET_PARAMETER_NAME);
			if(StringUtils.isNotBlank(targetParams)){
				serviceUrl = CasUrlUtils.addParameter(serviceUrl, TARGET_PARAMETER_NAME, targetParams,false);

			}
		}
		if (logger.isDebugEnabled()) {
			logger.debug("serviceUrl = " + serviceUrl);
		}
		return serviceUrl;
	}


	public void setAuthcProperties(SecurityCasAuthcProperties authcProperties) {
		this.authcProperties = authcProperties;
	}

	@Override
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		super.setAuthoritiesMapper(authoritiesMapper);
		this.authoritiesMapper = authoritiesMapper;
	}

}
