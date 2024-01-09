package org.springframework.security.boot.cas;

import org.jasig.cas.client.session.SessionMappingStorage;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.util.Objects;

public class CasSingleSignOutHttpSessionListener implements HttpSessionListener {

    private final SessionMappingStorage sessionMappingStorage;

    public CasSingleSignOutHttpSessionListener(SessionMappingStorage sessionMappingStorage) {
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
