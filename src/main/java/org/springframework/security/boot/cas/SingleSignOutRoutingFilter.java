package org.springframework.security.boot.cas;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.client.session.SessionMappingStorage;
import org.apereo.cas.client.session.SingleSignOutHandler;
import org.apereo.cas.client.util.AbstractConfigurationFilter;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SingleSignOutRoutingFilter.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
public class SingleSignOutRoutingFilter extends AbstractConfigurationFilter {

    private final AtomicBoolean handlerInitialized = new AtomicBoolean(false);
    private final SecurityCasAuthcProperties authcProperties;
    private final Map<String, SingleSignOutHandler> stringSingleSignOutHandlerMap = new ConcurrentHashMap<>();
    /** Mapping of token IDs and session IDs to HTTP sessions */
    private SessionMappingStorage sessionMappingStorage;
    private boolean eagerlyCreateSessions = true;

    public SingleSignOutRoutingFilter(SecurityCasAuthcProperties authcProperties, SessionMappingStorage sessionMappingStorage) {
        this.authcProperties = authcProperties;
        this.sessionMappingStorage = sessionMappingStorage;
        this.initSingleSignOutHandler(authcProperties.getServers());
    }

    private void initSingleSignOutHandler(List<SecurityCasServerProperties> servers) {

        /**
         * Set parameters in batch
         */
        PropertyMapper map = PropertyMapper.get();
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getServerUrlPrefix())
                    || stringSingleSignOutHandlerMap.containsKey(serverProperties.getServerUrlPrefix())) {
                continue;
            }
            try {

                SingleSignOutHandler singleSignOutHandler = new SingleSignOutHandler();

                map.from(sessionMappingStorage).to(singleSignOutHandler::setSessionMappingStorage);
                map.from(serverProperties.isArtifactParameterOverPost()).to(singleSignOutHandler::setArtifactParameterOverPost);
                map.from(serverProperties.getValidationType().getProtocol().getArtifactParameterName()).whenHasText().to(singleSignOutHandler::setArtifactParameterName);
                map.from(serverProperties.getLogoutCallbackPath()).to(singleSignOutHandler::setLogoutCallbackPath);
                map.from(serverProperties.getLogoutParameterName()).to(singleSignOutHandler::setLogoutParameterName);
                map.from(serverProperties.getRelayStateParameterName()).to(singleSignOutHandler::setRelayStateParameterName);
                map.from(eagerlyCreateSessions).to(singleSignOutHandler::setEagerlyCreateSessions);

                stringSingleSignOutHandlerMap.put(serverProperties.getServerUrlPrefix(), singleSignOutHandler);
            } catch (Exception e) {
                log.error("initTicketValidatorByTag error", e);
                // ignore
            }
        }
        handlerInitialized.set(true);
    }

    @Override
    /**
     * <p>Initializes the init.</p>
     * @param filterConfig
     */
    public void init(final FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        /**
         * <p>Workaround for now for the fact that Spring Security will fail since it doesn't call {@link #init(jakarta.servlet.FilterConfig)}.</p>
         * <p>Ultimately we need to allow deployers to actually inject their fully-initialized {@link org.apereo.cas.client.session.SingleSignOutHandler}.</p>
         */
        if (!this.handlerInitialized.getAndSet(true)) {
            this.initSingleSignOutHandler(authcProperties.getServers());
        }

        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        SingleSignOutHandler singleSignOutHandler = stringSingleSignOutHandlerMap.get(serverProperties.getServerUrlPrefix());

        if (singleSignOutHandler.process(request, response)) {
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }

    @Override
    /**
     * <p>Destroy.</p>
     */
    public void destroy() {
        // nothing to do
    }

    /**
     * <p>Sets the session mapping storage.</p>
     * @param sessionMappingStorage
     */
    public void setSessionMappingStorage(SessionMappingStorage sessionMappingStorage) {
        this.sessionMappingStorage = sessionMappingStorage;
    }

    /**
     * <p>Sets the eagerly create sessions.</p>
     * @param eagerlyCreateSessions
     */
    public void setEagerlyCreateSessions(boolean eagerlyCreateSessions) {
        this.eagerlyCreateSessions = eagerlyCreateSessions;
    }

}
