package org.springframework.security.boot.cas.ticket;

import net.rubyeye.xmemcached.XMemcachedClient;
import net.rubyeye.xmemcached.exception.MemcachedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.EhCacheBasedTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.util.Assert;

import java.util.concurrent.TimeoutException;

public class MemcachedBasedTicketCache implements StatelessTicketCache, InitializingBean {

    // ~ Static fields/initializers
    // =====================================================================================

    private static final Logger logger = LoggerFactory.getLogger(EhCacheBasedTicketCache.class);

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
            if (logger.isDebugEnabled()) {
                logger.debug("Cache hit: " + (token != null) + "; service ticket: " + serviceTicket);
            }
            return token == null ? null : (CasAuthenticationToken) token;
        } catch (TimeoutException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void putTicketInCache(final CasAuthenticationToken token) {
        if (logger.isDebugEnabled()) {
            logger.debug("Cache put: " + token.getCredentials().toString());
        }
        try {
            client.set(token.getCredentials().toString(), 0, token);
        } catch (TimeoutException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void removeTicketFromCache(final CasAuthenticationToken token) {
        if (logger.isDebugEnabled()) {
            logger.debug("Cache remove: " + token.getCredentials().toString());
        }
        this.removeTicketFromCache(token.getCredentials().toString());
    }

    @Override
    public void removeTicketFromCache(final String serviceTicket) {
        try {
            client.delete(serviceTicket);
        } catch (TimeoutException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (MemcachedException e) {
            throw new RuntimeException(e);
        }
    }

}
