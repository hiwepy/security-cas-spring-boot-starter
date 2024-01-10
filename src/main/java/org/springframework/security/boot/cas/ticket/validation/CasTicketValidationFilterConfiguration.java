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
package org.springframework.security.boot.cas.ticket.validation;


import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.proxy.ProxyRetriever;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.*;
import org.jasig.cas.client.validation.json.Cas30JsonProxyReceivingTicketValidationFilter;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.SecurityCasServerProperties.ValidationType;
import org.springframework.security.boot.cas.exception.CasAuthenticationServiceException;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

@Slf4j
public class CasTicketValidationFilterConfiguration {

    /* The storage location of the proxy granting tickets. */
    private ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider;

    /* Implementation of the proxy retriever. */
    private ProxyRetriever proxyRetriever;
    /**
     * Specifies whether any proxy is OK. Defaults to false.
     */
    private boolean acceptAnyProxy = false;
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

	public CasTicketValidationFilterConfiguration(ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
		this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
	}

    public AbstractTicketValidationFilter retrieveTicketValidationFilter(final TicketValidator ticketValidator,
                                                                         final SecurityCasServerProperties serverProperties) {
        if (serverProperties.getValidationType() == ValidationType.CAS10) {
            return buildCas10TicketValidationFilter(ticketValidator, serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS20_PROXY) {
            return buildCas20ProxyReceivingTicketValidationFilter(ticketValidator, serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS30_PROXY) {
            return buildCas30ProxyReceivingTicketValidationFilter(ticketValidator, serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.SAML) {
            return buildSaml11TicketValidationFilter(ticketValidator, serverProperties);
        } else {
            throw new CasAuthenticationServiceException("Unable to initialize the TicketValidationFilter for validationType: " + serverProperties.getValidationType());
        }
    }

    protected Cas10TicketValidationFilter buildCas10TicketValidationFilter(final TicketValidator ticketValidator,
                                                               final SecurityCasServerProperties serverProperties) {
        Cas10TicketValidationFilter validationFilter = new Cas10TicketValidationFilter();
        this.initTicketValidationFilter(validationFilter, serverProperties);
        return validationFilter;
    }

    protected Cas20ProxyReceivingTicketValidationFilter buildCas20ProxyReceivingTicketValidationFilter(final TicketValidator ticketValidator,
                                                             final SecurityCasServerProperties serverProperties) {
        Cas20ProxyReceivingTicketValidationFilter validationFilter = new Cas20ProxyReceivingTicketValidationFilter();
        this.initTicketValidationFilter(validationFilter, serverProperties);
        validationFilter.setMillisBetweenCleanUps(serverProperties.getMillisBetweenCleanUps());
        validationFilter.setProxyReceptorUrl(this.getProxyReceptorUrl());
        validationFilter.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        return validationFilter;
    }

    protected Cas30ProxyReceivingTicketValidationFilter buildCas30ProxyReceivingTicketValidationFilter(final TicketValidator ticketValidator,
                     final SecurityCasServerProperties serverProperties) {
        Cas30ProxyReceivingTicketValidationFilter validationFilter;
        if (serverProperties.getValidationResponse() == SecurityCasServerProperties.ValidationResponse.JSON) {
            validationFilter = new Cas30JsonProxyReceivingTicketValidationFilter();
        } else {
            validationFilter = new Cas30ProxyReceivingTicketValidationFilter();
        }
        this.initTicketValidationFilter(validationFilter, serverProperties);
        validationFilter.setMillisBetweenCleanUps(serverProperties.getMillisBetweenCleanUps());
        validationFilter.setProxyReceptorUrl(this.getProxyReceptorUrl());
        validationFilter.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        return validationFilter;
    }
    
    protected Saml11TicketValidationFilter buildSaml11TicketValidationFilter(final TicketValidator ticketValidator,
                                                                             final SecurityCasServerProperties serverProperties) {
    	final Saml11TicketValidationFilter validationFilter = new Saml11TicketValidationFilter();
        this.initTicketValidationFilter(validationFilter, serverProperties);
        return validationFilter;
    }

    protected void initTicketValidationFilter(final AbstractTicketValidationFilter validationFilter,
                                                                 final SecurityCasServerProperties serverProperties) {
        validationFilter.setEncodeServiceUrl(serverProperties.isEncodeServiceUrl());
        validationFilter.setExceptionOnValidationFailure(serverProperties.isExceptionOnValidationFailure());
        validationFilter.setIgnoreInitConfiguration(Boolean.TRUE);
        validationFilter.setRedirectAfterValidation(serverProperties.isRedirectAfterValidation());
        validationFilter.setService(serverProperties.getServiceUrl());
        validationFilter.setServerName(serverProperties.getClientHostUrl());
        validationFilter.setUseSession(serverProperties.isUseSession());
    }

	/*
	 * Gets the ssl config to use for HTTPS connections if one is configured for
	 * this filter.
	 * 
	 * @return Properties that can contains key/trust info for Client Side
	 *         Certificates
	 */
	protected Properties getSSLConfig(SecurityCasServerProperties serverProperties) {
		final Properties properties = new Properties();
		final String fileName = serverProperties.getSslConfigFile();

		if (fileName != null) {
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(fileName);
				properties.load(fis);
				log.trace("Loaded {} entries from {}", properties.size(), fileName);
			} catch (final IOException ioe) {
				log.error(ioe.getMessage(), ioe);
			} finally {
				CommonUtils.closeQuietly(fis);
			}
		}
		return properties;
	}

    public ProxyRetriever getProxyRetriever() {
        return proxyRetriever;
    }

    public void setProxyRetriever(ProxyRetriever proxyRetriever) {
        this.proxyRetriever = proxyRetriever;
    }

    public boolean isAcceptAnyProxy() {
        return acceptAnyProxy;
    }

    public void setAcceptAnyProxy(boolean acceptAnyProxy) {
        this.acceptAnyProxy = acceptAnyProxy;
    }

    public String getProxyReceptorUrl() {
        return proxyReceptorUrl;
    }

    public void setProxyReceptorUrl(String proxyReceptorUrl) {
        this.proxyReceptorUrl = proxyReceptorUrl;
    }

    public String getProxyCallbackUrl() {
        return proxyCallbackUrl;
    }

    public void setProxyCallbackUrl(String proxyCallbackUrl) {
        this.proxyCallbackUrl = proxyCallbackUrl;
    }
}
