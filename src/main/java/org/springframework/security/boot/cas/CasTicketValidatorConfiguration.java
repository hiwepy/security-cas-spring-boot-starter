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
import org.jasig.cas.client.proxy.Cas20ProxyRetriever;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyRetriever;
import org.jasig.cas.client.ssl.HttpURLConnectionFactory;
import org.jasig.cas.client.ssl.HttpsURLConnectionFactory;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.*;
import org.springframework.security.boot.SecurityCasAuthcProperties.CasProtocol;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.exception.CasAuthenticationServiceException;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;

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
    
	public CasTicketValidatorConfiguration(ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
		this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
	}

	/*
	 * Constructs a Cas20ServiceTicketValidator or a Cas20ProxyTicketValidator based on supplied parameters.
	 */
	public TicketValidator retrieveTicketValidator(final SecurityCasServerProperties serverProperties) {
        if (serverProperties.getProtocol() == CasProtocol.CAS10) {
            return buildCas10TicketValidator(serverProperties);
        } else if (serverProperties.getProtocol() == CasProtocol.CAS20) {
            return buildCas20TicketValidator(serverProperties);
        } else if (serverProperties.getProtocol() == CasProtocol.CAS20_PROXY) {
            return buildCas20ProxyTicketValidator(serverProperties);
        } else if (serverProperties.getProtocol() == CasProtocol.CAS30) {
            return buildCas30TicketValidator(serverProperties);
        } else if (serverProperties.getProtocol() == CasProtocol.CAS30_PROXY) {
            return buildCas30ProxyTicketValidator(serverProperties);
        } else if (serverProperties.getProtocol() == CasProtocol.SAML) {
            return buildSAMLTicketValidator(serverProperties);
        } else {
            throw new CasAuthenticationServiceException("Unable to initialize the TicketValidator for protocol: " + serverProperties.getProtocol());
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
       
        if( serverProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ServiceTicketValidator.setProxyCallbackUrl(serverProperties.getProxyCallbackUrl());
        	cas20ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas20ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas20ServiceTicketValidator;
    }

    protected TicketValidator buildCas20ProxyTicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas20ProxyTicketValidator cas20ProxyTicketValidator = new Cas20ProxyTicketValidator(serverProperties.getServerUrlPrefix());
        cas20ProxyTicketValidator.setEncoding(serverProperties.getEncoding());
        cas20ProxyTicketValidator.setRenew(serverProperties.getRenew());
        cas20ProxyTicketValidator.setAcceptAnyProxy(serverProperties.isAcceptAnyProxy());
        cas20ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(serverProperties.getAllowedProxyChains()));
        
        if( serverProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ProxyTicketValidator.setProxyCallbackUrl(serverProperties.getProxyCallbackUrl());
        	cas20ProxyTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas20ProxyTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
 
        return cas20ProxyTicketValidator;
    }

    protected TicketValidator buildCas30TicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas30ServiceTicketValidator cas30ServiceTicketValidator = new Cas30ServiceTicketValidator(serverProperties.getServerUrlPrefix());
        
        cas30ServiceTicketValidator.setEncoding(serverProperties.getEncoding());
        cas30ServiceTicketValidator.setRenew(serverProperties.getRenew());
       
        if( serverProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ServiceTicketValidator.setProxyCallbackUrl(serverProperties.getProxyCallbackUrl());
        	cas30ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties));
        	cas30ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas30ServiceTicketValidator;
    }

    protected TicketValidator buildCas30ProxyTicketValidator(final SecurityCasServerProperties serverProperties) {
        final Cas30ProxyTicketValidator cas30ProxyTicketValidator = new Cas30ProxyTicketValidator(serverProperties.getServerUrlPrefix());
        cas30ProxyTicketValidator.setEncoding(serverProperties.getEncoding());
        cas30ProxyTicketValidator.setRenew(serverProperties.getRenew());
        cas30ProxyTicketValidator.setAcceptAnyProxy(serverProperties.isAcceptAnyProxy());
        cas30ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(serverProperties.getAllowedProxyChains()));
        
        if( serverProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(serverProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(serverProperties.getServerUrlPrefix(), serverProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ProxyTicketValidator.setProxyCallbackUrl(serverProperties.getProxyCallbackUrl());
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

}
