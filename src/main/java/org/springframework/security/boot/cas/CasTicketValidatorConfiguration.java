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


import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;

import org.jasig.cas.client.proxy.Cas20ProxyRetriever;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyRetriever;
import org.jasig.cas.client.ssl.HttpURLConnectionFactory;
import org.jasig.cas.client.ssl.HttpsURLConnectionFactory;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Cas10TicketValidator;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Cas30ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasAuthcProperties.CasProtocol;
import org.springframework.security.boot.cas.exception.CasAuthenticationServiceException;


public class CasTicketValidatorConfiguration {

	protected final Logger logger = LoggerFactory.getLogger(CasTicketValidatorConfiguration.class);

    /* The storage location of the proxy granting tickets. */
    private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

    /* Implementation of the proxy retriever. */
    private ProxyRetriever proxyRetriever;
    
	public CasTicketValidatorConfiguration(ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
		this.proxyGrantingTicketStorage = proxyGrantingTicketStorage;
	}

	/*
	 * Constructs a Cas20ServiceTicketValidator or a Cas20ProxyTicketValidator based on supplied parameters.
	 */
	public TicketValidator retrieveTicketValidator(final SecurityCasAuthcProperties casProperties) {
        if (casProperties.getProtocol() == CasProtocol.CAS10) {
            return buildCas10TicketValidator(casProperties);
        } else if (casProperties.getProtocol() == CasProtocol.CAS20) {
            return buildCas20TicketValidator(casProperties);
        } else if (casProperties.getProtocol() == CasProtocol.CAS20_PROXY) {
            return buildCas20ProxyTicketValidator(casProperties);
        } else if (casProperties.getProtocol() == CasProtocol.CAS30) {
            return buildCas30TicketValidator(casProperties);
        } else if (casProperties.getProtocol() == CasProtocol.CAS30_PROXY) {
            return buildCas30ProxyTicketValidator(casProperties);
        } else if (casProperties.getProtocol() == CasProtocol.SAML) {
            return buildSAMLTicketValidator(casProperties);
        } else {
            throw new CasAuthenticationServiceException("Unable to initialize the TicketValidator for protocol: " + casProperties.getProtocol());
        }
    }

    protected TicketValidator buildCas10TicketValidator(final SecurityCasAuthcProperties casProperties) {
        final Cas10TicketValidator cas10TicketValidator = new Cas10TicketValidator(casProperties.getPrefixUrl());
        cas10TicketValidator.setEncoding(casProperties.getEncoding());
        cas10TicketValidator.setRenew(casProperties.isRenew());
        return cas10TicketValidator;
    }

    protected TicketValidator buildCas20TicketValidator(final SecurityCasAuthcProperties casProperties) {
        
    	final Cas20ServiceTicketValidator cas20ServiceTicketValidator = new Cas20ServiceTicketValidator(casProperties.getPrefixUrl());
        cas20ServiceTicketValidator.setEncoding(casProperties.getEncoding());
        cas20ServiceTicketValidator.setRenew(casProperties.isRenew());
       
        if( casProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(casProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(casProperties.getPrefixUrl(), casProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ServiceTicketValidator.setProxyCallbackUrl(casProperties.getProxyCallbackUrl());
        	cas20ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
        	cas20ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas20ServiceTicketValidator;
    }

    protected TicketValidator buildCas20ProxyTicketValidator(final SecurityCasAuthcProperties casProperties) {
        final Cas20ProxyTicketValidator cas20ProxyTicketValidator = new Cas20ProxyTicketValidator(casProperties.getPrefixUrl());
        cas20ProxyTicketValidator.setEncoding(casProperties.getEncoding());
        cas20ProxyTicketValidator.setRenew(casProperties.isRenew());
        cas20ProxyTicketValidator.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
        cas20ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(casProperties.getAllowedProxyChains()));
        
        if( casProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(casProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(casProperties.getPrefixUrl(), casProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas20ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas20ProxyTicketValidator.setProxyCallbackUrl(casProperties.getProxyCallbackUrl());
        	cas20ProxyTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
        	cas20ProxyTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
 
        return cas20ProxyTicketValidator;
    }

    protected TicketValidator buildCas30TicketValidator(final SecurityCasAuthcProperties casProperties) {
        final Cas30ServiceTicketValidator cas30ServiceTicketValidator = new Cas30ServiceTicketValidator(casProperties.getPrefixUrl());
        
        cas30ServiceTicketValidator.setEncoding(casProperties.getEncoding());
        cas30ServiceTicketValidator.setRenew(casProperties.isRenew());
       
        if( casProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(casProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(casProperties.getPrefixUrl(), casProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ServiceTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ServiceTicketValidator.setProxyCallbackUrl(casProperties.getProxyCallbackUrl());
        	cas30ServiceTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
        	cas30ServiceTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas30ServiceTicketValidator;
    }

    protected TicketValidator buildCas30ProxyTicketValidator(final SecurityCasAuthcProperties casProperties) {
        final Cas30ProxyTicketValidator cas30ProxyTicketValidator = new Cas30ProxyTicketValidator(casProperties.getPrefixUrl());
        cas30ProxyTicketValidator.setEncoding(casProperties.getEncoding());
        cas30ProxyTicketValidator.setRenew(casProperties.isRenew());
        cas30ProxyTicketValidator.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
        cas30ProxyTicketValidator.setAllowedProxyChains(CommonUtils.createProxyList(casProperties.getAllowedProxyChains()));
        
        if( casProperties.isAcceptAnyProxy()) {
        	
        	HttpURLConnectionFactory urlConnectionFactory = new HttpsURLConnectionFactory( HttpsURLConnection.getDefaultHostnameVerifier(), getSSLConfig(casProperties));
        	if(proxyRetriever == null) {
        		proxyRetriever = new Cas20ProxyRetriever(casProperties.getPrefixUrl(), casProperties.getEncoding(), urlConnectionFactory);
        	}
        	cas30ProxyTicketValidator.setProxyRetriever(proxyRetriever);
        	cas30ProxyTicketValidator.setProxyCallbackUrl(casProperties.getProxyCallbackUrl());
        	cas30ProxyTicketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
        	cas30ProxyTicketValidator.setURLConnectionFactory(urlConnectionFactory);
        }
        return cas30ProxyTicketValidator;
    }
    
    protected TicketValidator buildSAMLTicketValidator(final SecurityCasAuthcProperties casProperties) {
    	 final Saml11TicketValidator saml11TicketValidator = new Saml11TicketValidator(casProperties.getPrefixUrl());
         saml11TicketValidator.setTolerance(casProperties.getTolerance());
         saml11TicketValidator.setEncoding(casProperties.getEncoding());
         saml11TicketValidator.setRenew(casProperties.isRenew());
         saml11TicketValidator.setCustomParameters(casProperties.getCustomParams());
        return saml11TicketValidator;
    }
	
	/*
	 * Gets the ssl config to use for HTTPS connections if one is configured for
	 * this filter.
	 * 
	 * @return Properties that can contains key/trust info for Client Side
	 *         Certificates
	 */
	protected Properties getSSLConfig(SecurityCasAuthcProperties casProperties) {
		final Properties properties = new Properties();
		final String fileName = casProperties.getSslConfigFile();

		if (fileName != null) {
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(fileName);
				properties.load(fis);
				logger.trace("Loaded {} entries from {}", properties.size(), fileName);
			} catch (final IOException ioe) {
				logger.error(ioe.getMessage(), ioe);
			} finally {
				CommonUtils.closeQuietly(fis);
			}
		}
		return properties;
	}

}
