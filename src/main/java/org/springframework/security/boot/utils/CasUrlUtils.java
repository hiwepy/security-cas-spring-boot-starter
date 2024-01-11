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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasServerProperties;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class CasUrlUtils {

	/**
	 * Note that trailing slashes should not be used in the serverName.  As a convenience for this common misconfiguration, we strip them from the provided
	 * value.
	 *
	 * @param serverProperties the server properties
	 */
	public static String getServerName(SecurityCasServerProperties serverProperties) {
		try {
			URI uri = new URI(serverProperties.getClientHostUrl());
			String serverName = uri.getHost();
			// 移除可能存在的尾部斜杠
			if (serverName.endsWith("/")) {
				serverName = serverName.substring(0, serverName.length() - 1);
			}
			log.info("Eliminated extra slash from serverName [{}].  It is now [{}]", serverProperties.getClientHostUrl(), serverName);
			return serverName;
		} catch (URISyntaxException e) {
			log.error("Error parsing URL {}", serverProperties.getClientHostUrl(), e.getMessage());
			return serverProperties.getClientHostUrl();
        }
	}

	/**
	 * 获取字段值
	 *
	 * @param urlStr URL
	 * @param field 字段名
	 * @return
	 */
	public static String getFieldValue(String urlStr, String field) {
		String result = "";
		Pattern pXM = Pattern.compile(field + "=([^&]*)");
		Matcher mXM = pXM.matcher(urlStr);
		while (mXM.find()) {
			result += mXM.group(1);
		}
		return result;
	}

	public static String constructLogoutRedirectUrl(SecurityCasServerProperties serverProperties) {
		return CommonUtils.constructRedirectUrl(serverProperties.getServerLogoutUrl(),
				serverProperties.getValidationType().getProtocol().getServiceParameterName(),
				serverProperties.getServiceUrl(), serverProperties.getRenew(), serverProperties.getGateway());
	}

	public static String constructLoginRedirectUrl(SecurityCasServerProperties serverProperties) {
		return CommonUtils.constructRedirectUrl(serverProperties.getServerLoginUrl(),
				serverProperties.getValidationType().getProtocol().getServiceParameterName(),
				serverProperties.getServiceUrl(), serverProperties.getRenew(), serverProperties.getGateway());
	}

	/**
	 * Constructs the Url for Redirection to the CAS server. Default implementation relies
	 * on the CAS client to do the bulk of the work.
	 *
	 * @param serverProperties the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	public static String constructRedirectUrl(HttpServletRequest request, SecurityCasServerProperties serverProperties) {
		//追加重定向路由
		String targetUrl = request.getParameter(serverProperties.getTargetUrlParameter());
		String serviceUrl = serverProperties.getServiceUrl();
		if(StringUtils.isNotBlank(targetUrl)){
			serviceUrl = CasUrlUtils.addParameter(serviceUrl,serverProperties.getTargetUrlParameter(),targetUrl,false);
		}
		return CommonUtils.constructRedirectUrl(serverProperties.getServerLoginUrl(),
				serverProperties.getValidationType().getProtocol().getServiceParameterName(), serviceUrl,
				serverProperties.getRenew(), false);
	}
	
	/**
	 * Constructs the Url for Redirection to the CAS server. Default implementation relies
	 * on the CAS client to do the bulk of the work.
	 *
	 * @param serverProperties the service url that should be included.
	 * @return the redirect url. CANNOT be NULL.
	 */
	public static String constructFailureRedirectUrl(SecurityCasServerProperties serverProperties) {
		return CommonUtils.constructRedirectUrl(serverProperties.getServerLoginUrl(),
				serverProperties.getValidationType().getProtocol().getServiceParameterName(), serverProperties.getFailureUrl(),
				serverProperties.getRenew(), false);
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
