package org.springframework.security.boot.cas;

import org.apereo.cas.client.session.SessionMappingStorage;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import java.util.Objects;

public class SingleSignOutHttpSessionCasListener implements HttpSessionListener {

    private final SessionMappingStorage sessionMappingStorage;

    public SingleSignOutHttpSessionCasListener(SessionMappingStorage sessionMappingStorage) {
        this.sessionMappingStorage = sessionMappingStorage;
    }

    @Override
    public void sessionCreated(final HttpSessionEvent event) {
        // nothing to do at the moment
    }

    @Override
    public void sessionDestroyed(final HttpSessionEvent event) {
        if (Objects.nonNull(sessionMappingStorage)) {
            final HttpSession session = event.getSession();
            sessionMappingStorage.removeBySessionById(session.getId());
        }
    }

}
