package org.springframework.security.boot.cas;

import org.apereo.cas.client.session.SessionMappingStorage;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.util.Objects;
/**
 * SingleSignOutHttpSessionCasListener.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class SingleSignOutHttpSessionCasListener implements HttpSessionListener {

    private final SessionMappingStorage sessionMappingStorage;

    public SingleSignOutHttpSessionCasListener(SessionMappingStorage sessionMappingStorage) {
        this.sessionMappingStorage = sessionMappingStorage;
    }

    @Override
    /**
     * <p>Session created.</p>
     * @param event
     */
    public void sessionCreated(final HttpSessionEvent event) {
        // nothing to do at the moment
    }

    @Override
    /**
     * <p>Session destroyed.</p>
     * @param event
     */
    public void sessionDestroyed(final HttpSessionEvent event) {
        if (Objects.nonNull(sessionMappingStorage)) {
            final HttpSession session = event.getSession();
            sessionMappingStorage.removeBySessionById(session.getId());
        }
    }

}
