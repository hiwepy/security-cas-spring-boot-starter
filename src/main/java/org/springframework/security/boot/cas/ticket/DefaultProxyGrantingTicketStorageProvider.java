package org.springframework.security.boot.cas.ticket;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class DefaultProxyGrantingTicketStorageProvider implements ProxyGrantingTicketStorageProvider {

    private Map<String, ProxyGrantingTicketStorage> proxyGrantingTicketStorageMap = new ConcurrentHashMap<>();

    public DefaultProxyGrantingTicketStorageProvider(SecurityCasAuthcProperties authcProperties) {
        this.initProxyGrantingTicketStorage(authcProperties.getServers());
    }

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

    protected ProxyGrantingTicketStorage buildProxyGrantingTicketStorage(SecurityCasServerProperties serverProperties) {
        if (Objects.isNull(serverProperties)) {
            return null;
        }
        return new ProxyGrantingTicketStorageImpl(serverProperties.getTicketTimeout());
    }

    @Override
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
