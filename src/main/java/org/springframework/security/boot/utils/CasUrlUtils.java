/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.springframework.security.boot.utils;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;

public class CasUrlUtils {

	public static String constructCallbackUrl(String serviceUrl, String callbackUrl) {
		return serviceUrl + (serviceUrl.endsWith("/") ? "" : "/") + callbackUrl;
	}
	
	public static String constructLogoutRedirectUrl(SecurityCasAuthcProperties authcProperties) {
		return CommonUtils.constructRedirectUrl(authcProperties.getLogoutUrl(), authcProperties.getServiceParameterName(),
				authcProperties.getServiceUrl(), authcProperties.isRenew(), authcProperties.isGateway());
	}

	public static String constructLoginRedirectUrl(SecurityCasAuthcProperties authcProperties) {
		return CommonUtils.constructRedirectUrl(authcProperties.getLoginUrl(), authcProperties.getServiceParameterName(),
				authcProperties.getServiceUrl(), authcProperties.isRenew(), authcProperties.isGateway());
	}

	/**
	 * Constructs the Url for Redirection to the CAS server. Default implementation relies
	 * on the CAS client to do the bulk of the work.
	 *
	 * @param serviceUrl the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	public static String constructRedirectUrl(SecurityCasAuthcProperties authcProperties) {
		String callbackUrl = constructCallbackUrl(authcProperties.getServiceUrl(), authcProperties.getServiceCallback());
		return CommonUtils.constructRedirectUrl(authcProperties.getLoginUrl(),
				authcProperties.getServiceParameterName(), callbackUrl,
				authcProperties.isRenew(), false);
	}
	
}
