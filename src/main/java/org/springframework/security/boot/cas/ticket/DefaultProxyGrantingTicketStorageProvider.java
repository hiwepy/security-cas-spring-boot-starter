package org.springframework.security.boot.cas.ticket;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.client.proxy.ProxyGrantingTicketStorage;
import org.apereo.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DefaultProxyGrantingTicketStorageProvider.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
public class DefaultProxyGrantingTicketStorageProvider implements ProxyGrantingTicketStorageProvider {

    private Map<String, ProxyGrantingTicketStorage> proxyGrantingTicketStorageMap = new ConcurrentHashMap<>();

    /**
     * Constructs a new default proxy granting ticket storage provider instance.
     *
     * @param authcProperties the authc properties
     */
    public DefaultProxyGrantingTicketStorageProvider(SecurityCasAuthcProperties authcProperties) {
        this.initProxyGrantingTicketStorage(authcProperties.getServers());
    }

    /**
     * <p>Initializes the proxy granting ticket storage.</p>
     * @param servers
     */
    protected void initProxyGrantingTicketStorage(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (StringUtils.hasText(serverProperties.getServerUrlPrefix())
                    || proxyGrantingTicketStorageMap.containsKey(serverProperties.getServerUrlPrefix())) {
                continue;
            }
            try {
                proxyGrantingTicketStorageMap.put(serverProperties.getServerUrlPrefix(), this.buildProxyGrantingTicketStorage(serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByReferer error", e);
                // ignore
            }
        }
    }

    /**
     * <p>Builds the proxy granting ticket storage.</p>
     * @param serverProperties
     * @return the build proxy granting ticket storage
     */
    protected ProxyGrantingTicketStorage buildProxyGrantingTicketStorage(SecurityCasServerProperties serverProperties) {
        if (Objects.isNull(serverProperties)) {
            return null;
        }
        return new ProxyGrantingTicketStorageImpl(serverProperties.getTicketTimeout());
    }

    @Override
    /**
     * <p>Returns the proxy granting ticket storage.</p>
     * @param serverProperties
     * @return the get proxy granting ticket storage
     */
    public ProxyGrantingTicketStorage getProxyGrantingTicketStorage(SecurityCasServerProperties serverProperties) {
        if (Objects.isNull(serverProperties)) {
            return null;
        }
        if (StringUtils.hasText(serverProperties.getServerUrlPrefix())
                && proxyGrantingTicketStorageMap.containsKey(serverProperties.getServerUrlPrefix())) {
            return proxyGrantingTicketStorageMap.get(serverProperties.getServerUrlPrefix());
        }
        return this.buildProxyGrantingTicketStorage(serverProperties);
    }

}
