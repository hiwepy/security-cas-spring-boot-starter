package org.springframework.security.boot.cas.ticket;

import org.apereo.cas.client.proxy.ProxyGrantingTicketStorage;
import org.springframework.security.boot.SecurityCasServerProperties;
/**
 * ProxyGrantingTicketStorageProvider.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public interface ProxyGrantingTicketStorageProvider {

    ProxyGrantingTicketStorage getProxyGrantingTicketStorage(SecurityCasServerProperties serverProperties);

}
