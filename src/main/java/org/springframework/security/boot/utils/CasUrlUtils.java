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
package org.springframework.security.boot.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;

import javax.servlet.http.HttpServletRequest;

public class CasUrlUtils {

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
	 * @param authcProperties the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	public static String constructRedirectUrl(HttpServletRequest request,SecurityCasAuthcProperties authcProperties) {
		//追加重定向路由
		String targetUrl = request.getParameter(authcProperties.getTargetUrlParameter());
		String serviceUrl = authcProperties.getServiceUrl();
		if(StringUtils.isNotBlank(targetUrl)){
			serviceUrl = CasUrlUtils.addParameter(serviceUrl,authcProperties.getTargetUrlParameter(),targetUrl,false);
		}
		return CommonUtils.constructRedirectUrl(authcProperties.getLoginUrl(),
				authcProperties.getServiceParameterName(), serviceUrl,
				authcProperties.isRenew(), false);
	}
	
	/**
	 * Constructs the Url for Redirection to the CAS server. Default implementation relies
	 * on the CAS client to do the bulk of the work.
	 *
	 * @param authcProperties the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	public static String constructFailureRedirectUrl(SecurityCasAuthcProperties authcProperties) {
		return CommonUtils.constructRedirectUrl(authcProperties.getLoginUrl(),
				authcProperties.getServiceParameterName(), authcProperties.getFailureUrl(),
				authcProperties.isRenew(), false);
	}
	
    /**
     * Add a new parameter to an url.
     *
     * @param url   url
     * @param name  name of the parameter
     * @param value value of the parameter
     * @return the new url with the parameter appended
     */
    public static String addParameter(final String url, final String name, final String value,final Boolean encodeFlag) {
        if (url != null) {
            final StringBuilder sb = new StringBuilder();
            sb.append(url);
            if (name != null) {
                if (url.indexOf("?") >= 0) {
                    sb.append("&");
                } else {
                    sb.append("?");
                }
                sb.append(name);
                sb.append("=");
                if (value != null) {
					if(encodeFlag){
						sb.append(urlEncode(value));
					}else{
						sb.append(value);
					}

                }
            }
            return sb.toString();
        }
        return null;
    }

    /**
     * URL encode a text using UTF-8.
     *
     * @param text text to encode
     * @return the encoded text
     */
    public static String urlEncode(final String text) {
        try {
            return URLEncoder.encode(text, StandardCharsets.UTF_8.name());
        } catch (final UnsupportedEncodingException e) {
            final String message = "Unable to encode text : " + text;
            throw new RuntimeException(message, e);
        }
    }
	
}
