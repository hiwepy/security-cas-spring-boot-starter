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

import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.web.util.WebUtils;

public class CasUrlUtils {

	public static String constructCallbackUrl(String contextPath, String serverUrl) {
		contextPath = StringUtils.hasText(contextPath) ? contextPath : "/";
		if (contextPath.endsWith("/")) {
			contextPath = contextPath.substring(0, contextPath.length() - 1);
		}
		StringBuilder callbackUrlBuilder = new StringBuilder(contextPath).append(serverUrl);
		return callbackUrlBuilder.toString();
	}
	
	public static String constructCallbackUrl(SecurityCasAuthcProperties casProperties, String contextPath, String serverUrl) {

		contextPath = StringUtils.hasText(contextPath) ? contextPath : "/";
		if (contextPath.endsWith("/")) {
			contextPath = contextPath.substring(0, contextPath.length() - 1);
		}
		
		try {
			
			URL url = new URL(casProperties.getService());
			
			// 重定向地址：用于重新回到业务系统
			StringBuilder callbackUrl = new StringBuilder(url.getProtocol()).append("://").append(url.getHost())
					.append( url.getPort() != -1 ? ":" + url.getPort() : "").append(contextPath).append(serverUrl);

			return callbackUrl.toString();
			
		} catch (MalformedURLException e) {
			// 重定向地址：用于重新回到业务系统
			StringBuilder callbackUrl = new StringBuilder(casProperties.getService()).append(contextPath).append(serverUrl);
			return callbackUrl.toString();
		}

	}
	
	public static String constructRedirectUrl(SecurityCasAuthcProperties casProperties, String casServerPath, String contextPath, String serverUrl)  {

		StringBuilder casRedirectUrl = new StringBuilder(casProperties.getPrefixUrl());
		if (!casRedirectUrl.toString().endsWith("/")) {
			casRedirectUrl.append("/");
		}
		casRedirectUrl.append(casServerPath);
		
		String callbackUrl = CasUrlUtils.constructCallbackUrl(casProperties, contextPath, serverUrl);
		
		return CommonUtils.constructRedirectUrl(casRedirectUrl.toString(), casProperties.getServiceParameterName(), callbackUrl, casProperties.isRenew(), casProperties.isGateway());
		
	}
	
	public static String constructLogoutRedirectUrl(SecurityCasAuthcProperties casProperties, String contextPath, String serverUrl){
		String callbackUrl = CasUrlUtils.constructCallbackUrl(casProperties, contextPath, serverUrl);
		return CommonUtils.constructRedirectUrl(casProperties.getLogoutUrl(), casProperties.getServiceParameterName(), callbackUrl, casProperties.isRenew(), casProperties.isGateway());
	}
	
	public static String constructLoginRedirectUrl(SecurityCasAuthcProperties casProperties, String contextPath, String serverUrl){
		String callbackUrl = CasUrlUtils.constructCallbackUrl(casProperties, contextPath, serverUrl);
		return CommonUtils.constructRedirectUrl(casProperties.getLogoutUrl(), casProperties.getServiceParameterName(), callbackUrl, casProperties.isRenew(), casProperties.isGateway());
	}
	
	public static String constructServiceUrl(ServletRequest request, ServletResponse response, SecurityCasAuthcProperties casProperties) {
		
		return CommonUtils.constructServiceUrl(WebUtils.getNativeRequest(request, HttpServletRequest.class), 
				WebUtils.getNativeResponse(response, HttpServletResponse.class), casProperties.getService(),
				casProperties.getService(), casProperties.getServiceParameterName(),
				casProperties.getArtifactParameterName(), casProperties.isEncodeServiceUrl());
		
	}
	
}
