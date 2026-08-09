package org.springframework.security.boot.cas.ticket;

import lombok.extern.slf4j.Slf4j;
import net.rubyeye.xmemcached.XMemcachedClient;
import net.rubyeye.xmemcached.exception.MemcachedException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.util.Assert;

import java.util.concurrent.TimeoutException;

/**
 * MemcachedBasedTicketCache.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Slf4j
public class MemcachedBasedTicketCache implements StatelessTicketCache, InitializingBean {


    // ~ Instance fields
    // ================================================================================================

    private XMemcachedClient client;

    public MemcachedBasedTicketCache(XMemcachedClient client) {
        this.client = client;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(client, "client mandatory");
    }

    @Override
    public CasAuthenticationToken getByTicketId(final String serviceTicket) {
        try {
            Object token = client.get(serviceTicket);
            if (log.isDebugEnabled()) {
                log.debug("Cache hit: {}; service ticket: {}", token != null, serviceTicket);
            }
            return token == null ? null : (CasAuthenticationToken) token;
        } catch (TimeoutException | InterruptedException | MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void putTicketInCache(final CasAuthenticationToken token) {
        if (log.isDebugEnabled()) {
            log.debug("Cache put: {}", token.getCredentials().toString());
        }
        try {
            client.set(token.getCredentials().toString(), 0, token);
        } catch (TimeoutException | InterruptedException | MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void removeTicketFromCache(final CasAuthenticationToken token) {
        if (log.isDebugEnabled()) {
            log.debug("Cache remove: {}", token.getCredentials().toString());
        }
        this.removeTicketFromCache(token.getCredentials().toString());
    }

    @Override
    public void removeTicketFromCache(final String serviceTicket) {
        try {
            client.delete(serviceTicket);
        } catch (TimeoutException | InterruptedException | MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

}
