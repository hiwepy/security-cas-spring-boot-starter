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
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.Cas20ProxyRetriever;
import org.jasig.cas.client.proxy.ProxyRetriever;
import org.jasig.cas.client.ssl.AnyHostnameVerifier;
import org.jasig.cas.client.ssl.HttpURLConnectionFactory;
import org.jasig.cas.client.ssl.HttpsURLConnectionFactory;
import org.jasig.cas.client.ssl.WhitelistHostnameVerifier;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.*;
import org.jasig.cas.client.validation.json.Cas30JsonServiceTicketValidator;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.SecurityCasServerProperties.ValidationType;
import org.springframework.security.boot.SecurityCasServerProperties.ValidationResponse;
import org.springframework.security.boot.cas.exception.CasAuthenticationServiceException;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

@Slf4j
public class CasTicketValidatorConfiguration {

    /* The storage location of the proxy granting tickets. */
    private ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider;

    /* Implementation of the proxy retriever. */
    private ProxyRetriever proxyRetriever;

    private HostnameVerifier hostnameVerifier = new AnyHostnameVerifier();

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
    
	public CasTicketValidatorConfiguration(ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
		this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
	}

	/*
	 * Constructs a Cas20ServiceTicketValidator or a Cas20ProxyTicketValidator based on supplied parameters.
	 */
	public TicketValidator retrieveTicketValidator(final SecurityCasServerProperties serverProperties) {
        if (serverProperties.getValidationType() == ValidationType.CAS10) {
            return buildCas10TicketValidator(serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS20) {
            return buildCas20TicketValidator(serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS20_PROXY) {
            return buildCas20ProxyTicketValidator(serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS30) {
            return buildCas30TicketValidator(serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.CAS30_PROXY) {
            return buildCas30ProxyTicketValidator(serverProperties);
        } else if (serverProperties.getValidationType() == ValidationType.SAML) {
            return buildSAMLTicketValidator(serverProperties);
        } else {
            throw new CasAuthenticationServiceException("Unable to initialize the TicketValidator for Type: " + serverProperties.getValidationType());
        }
    }

    protected TicketValidator buildCas10TicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas10TicketValidator cas10TicketValidator = new Cas10TicketValidator(serverProperties.getServerUrlPrefix());
        cas10TicketValidator.setEncoding(serverProperties.getEncoding());
        cas10TicketValidator.setRenew(serverProperties.getRenew());
        return cas10TicketValidator;
    }

    protected TicketValidator buildCas20TicketValidator(final SecurityCasServerProperties serverProperties) {
        
    	final Cas20ServiceTicketValidator cas20ServiceTicketValidator = new Cas20ServiceTicketValidator(serverProperties.getServerUrlPrefix());
        cas20ServiceTicketValidator.setEncoding(serverProperties.getEncoding());
        cas20ServiceTicketValidator.setRenew(serverProperties.getRenew());
       
        if( this.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ServiceTicketValidator.setProxyCallbackUrl(this.getProxyCallbackUrl());
        	cas20ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas20ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas20ServiceTicketValidator;
    }

    protected TicketValidator buildCas20ProxyTicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas20ProxyTicketValidator cas20ProxyTicketValidator = new Cas20ProxyTicketValidator(serverProperties.getServerUrlPrefix());
        cas20ProxyTicketValidator.setEncoding(serverProperties.getEncoding());
        cas20ProxyTicketValidator.setRenew(serverProperties.getRenew());
        cas20ProxyTicketValidator.setAcceptAnyProxy(this.isAcceptAnyProxy());
        cas20ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(serverProperties.getAllowedProxyChains()));
        
        if( this.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ProxyTicketValidator.setProxyCallbackUrl(this.getProxyCallbackUrl());
        	cas20ProxyTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas20ProxyTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
 
        return cas20ProxyTicketValidator;
    }

    protected TicketValidator buildCas30TicketValidator(final SecurityCasServerProperties serverProperties) {

        Cas30ServiceTicketValidator cas30ServiceTicketValidator = null;
        if (serverProperties.getValidationResponse() == ValidationResponse.JSON) {
            cas30ServiceTicketValidator = new Cas30JsonServiceTicketValidator(serverProperties.getServerUrlPrefix());
        } else {
            cas30ServiceTicketValidator = new Cas30ServiceTicketValidator(serverProperties.getServerUrlPrefix());
        }

        cas30ServiceTicketValidator.setEncoding(serverProperties.getEncoding());
        cas30ServiceTicketValidator.setRenew(serverProperties.getRenew());
       
        if( this.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ServiceTicketValidator.setProxyCallbackUrl(this.getProxyCallbackUrl());
        	cas30ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas30ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas30ServiceTicketValidator;
    }

    protected TicketValidator buildCas30ProxyTicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas30ProxyTicketValidator cas30ProxyTicketValidator = new Cas30ProxyTicketValidator(serverProperties.getServerUrlPrefix());
        cas30ProxyTicketValidator.setEncoding(serverProperties.getEncoding());
        cas30ProxyTicketValidator.setRenew(serverProperties.getRenew());
        cas30ProxyTicketValidator.setAcceptAnyProxy(this.isAcceptAnyProxy());
        cas30ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(serverProperties.getAllowedProxyChains()));
        
        if( this.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ProxyTicketValidator.setProxyCallbackUrl(this.getProxyCallbackUrl());
        	cas30ProxyTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas30ProxyTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas30ProxyTicketValidator;
    }
    
    protected TicketValidator buildSAMLTicketValidator(final SecurityCasServerProperties serverProperties) {
        final Saml11TicketValidator saml11TicketValidator = new Saml11TicketValidator(serverProperties.getServerUrlPrefix());
        saml11TicketValidator.setTolerance(serverProperties.getTolerance());
        saml11TicketValidator.setEncoding(serverProperties.getEncoding());
        saml11TicketValidator.setRenew(serverProperties.getRenew());
        saml11TicketValidator.setCustomParameters(serverProperties.getCustomParams());
        final HttpURLConnectionFactory factory = new HttpsURLConnectionFactory(hostnameVerifier, getSSLConfig(serverProperties));
        saml11TicketValidator.setURLConnectionFactory(factory);

        return saml11TicketValidator;
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

    public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
        this.hostnameVerifier = hostnameVerifier;
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