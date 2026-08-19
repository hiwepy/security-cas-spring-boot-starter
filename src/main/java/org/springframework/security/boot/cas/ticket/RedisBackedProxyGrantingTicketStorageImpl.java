package org.springframework.security.boot.cas.ticket;

import org.apereo.cas.client.proxy.AbstractEncryptedProxyGrantingTicketStorageImpl;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
/**
 * RedisBackedProxyGrantingTicketStorageImpl.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class RedisBackedProxyGrantingTicketStorageImpl extends
        AbstractEncryptedProxyGrantingTicketStorageImpl {
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisBackedProxyGrantingTicketStorageImpl(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    /**
     * <p>Save internal.</p>
     * @param proxyGrantingTicketIou
     * @param proxyGrantingTicket
     */
    public void saveInternal(final String proxyGrantingTicketIou, final String proxyGrantingTicket) {
        handleSynchronousRequest(CompletableFuture.supplyAsync(() -> {
            redisTemplate.opsForValue().set(proxyGrantingTicketIou, proxyGrantingTicket, Duration.ofSeconds(120));
            return null;
        }));
    }

    @Override
    /**
     * <p>Retrieve internal.</p>
     * @param proxyGrantingTicketIou
     * @return the retrieve internal
     */
    public String retrieveInternal(final String proxyGrantingTicketIou) {
        return (String) redisTemplate.opsForValue().get(proxyGrantingTicketIou);
    }

    @Override
    /**
     * <p>Clean up.</p>
     */
    public void cleanUp() {
        // we actually don't have anything to do here, yay!
    }

    private void handleSynchronousRequest(final Future<?> f) {
        try {
            f.get();
        } catch (final Exception e) {
            // ignore these.
        }
    }
}
