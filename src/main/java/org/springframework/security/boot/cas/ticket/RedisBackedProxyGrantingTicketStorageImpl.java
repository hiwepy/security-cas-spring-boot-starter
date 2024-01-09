package org.springframework.security.boot.cas.ticket;

import org.jasig.cas.client.proxy.AbstractEncryptedProxyGrantingTicketStorageImpl;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

public class RedisBackedProxyGrantingTicketStorageImpl extends
        AbstractEncryptedProxyGrantingTicketStorageImpl {
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisBackedProxyGrantingTicketStorageImpl(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void saveInternal(final String proxyGrantingTicketIou, final String proxyGrantingTicket) {
        handleSynchronousRequest(CompletableFuture.supplyAsync(() -> {
            redisTemplate.opsForValue().set(proxyGrantingTicketIou, proxyGrantingTicket, Duration.ofSeconds(120));
            return null;
        }));
    }

    @Override
    public String retrieveInternal(final String proxyGrantingTicketIou) {
        return (String) redisTemplate.opsForValue().get(proxyGrantingTicketIou);
    }

    @Override
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
