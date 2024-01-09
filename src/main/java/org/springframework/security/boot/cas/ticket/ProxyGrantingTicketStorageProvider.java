package org.springframework.security.boot.cas.ticket;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.springframework.security.boot.SecurityCasServerProperties;

public interface ProxyGrantingTicketStorageProvider {

    ProxyGrantingTicketStorage getProxyGrantingTicketStorage(SecurityCasServerProperties serverProperties);

}
