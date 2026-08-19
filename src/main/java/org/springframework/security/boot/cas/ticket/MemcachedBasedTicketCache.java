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
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
public class MemcachedBasedTicketCache implements StatelessTicketCache, InitializingBean {


    // ~ Instance fields
    // ================================================================================================

    private XMemcachedClient client;

    /**
     * Constructs a new memcached based ticket cache instance.
     *
     * @param client the client
     */
    public MemcachedBasedTicketCache(XMemcachedClient client) {
        this.client = client;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    /**
     * <p>After properties set.</p>
     */
    public void afterPropertiesSet() {
        Assert.notNull(client, "client mandatory");
    }

    @Override
    /**
     * <p>Returns the by ticket id.</p>
     * @param serviceTicket
     * @return the get by ticket id
     */
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
    /**
     * <p>Put ticket in cache.</p>
     * @param token
     */
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
    /**
     * <p>Remove ticket from cache.</p>
     * @param token
     */
    public void removeTicketFromCache(final CasAuthenticationToken token) {
        if (log.isDebugEnabled()) {
            log.debug("Cache remove: {}", token.getCredentials().toString());
        }
        this.removeTicketFromCache(token.getCredentials().toString());
    }

    @Override
    /**
     * <p>Remove ticket from cache.</p>
     * @param serviceTicket
     */
    public void removeTicketFromCache(final String serviceTicket) {
        try {
            client.delete(serviceTicket);
        } catch (TimeoutException | InterruptedException | MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

}
