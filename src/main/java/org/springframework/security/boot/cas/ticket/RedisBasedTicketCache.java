package org.springframework.security.boot.cas.ticket;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.util.Assert;
/**
 * RedisBasedTicketCache.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
public class RedisBasedTicketCache implements StatelessTicketCache, InitializingBean {

    // ~ Instance fields
    // ================================================================================================

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisBasedTicketCache(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    /**
     * <p>After properties set.</p>
     */
    public void afterPropertiesSet() {
        Assert.notNull(redisTemplate, "redisTemplate mandatory");
    }

    @Override
    /**
     * <p>Returns the by ticket id.</p>
     * @param serviceTicket
     * @return the get by ticket id
     */
    public CasAuthenticationToken getByTicketId(final String serviceTicket) {
        Object token = redisTemplate.opsForValue().get(serviceTicket);
        if (log.isDebugEnabled()) {
            log.debug("Cache hit: {}; service ticket: {}", token != null, serviceTicket);
        }
        return token == null ? null : (CasAuthenticationToken) token;
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
        redisTemplate.opsForValue().set(token.getCredentials().toString(), token);
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
        redisTemplate.delete(serviceTicket);
    }

}
