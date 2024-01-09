package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutHandler;
import org.jasig.cas.client.util.AbstractConfigurationFilter;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
public class CasSingleSignOutFilter extends AbstractConfigurationFilter {

    private final AtomicBoolean handlerInitialized = new AtomicBoolean(false);
    private final SecurityCasAuthcProperties authcProperties;
    private final Map<String, SingleSignOutHandler> stringSingleSignOutHandlerMap = new ConcurrentHashMap<>();
    /** Mapping of token IDs and session IDs to HTTP sessions */
    private SessionMappingStorage sessionMappingStorage;
    private boolean eagerlyCreateSessions = true;

    public CasSingleSignOutFilter(SecurityCasAuthcProperties authcProperties, SessionMappingStorage sessionMappingStorage) {
        this.authcProperties = authcProperties;
        this.sessionMappingStorage = sessionMappingStorage;
        this.initSingleSignOutHandler(authcProperties.getServers());
    }

    private void initSingleSignOutHandler(List<SecurityCasServerProperties> servers) {

        /**
         * 批量设置参数
         */
        PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getServerUrlPrefix())
                    || stringSingleSignOutHandlerMap.containsKey(serverProperties.getServerUrlPrefix())) {
                continue;
            }
            try {

                SingleSignOutHandler singleSignOutHandler = new SingleSignOutHandler();

                map.from(sessionMappingStorage).whenNonNull().to(singleSignOutHandler::setSessionMappingStorage);
                map.from(serverProperties.isArtifactParameterOverPost()).to(singleSignOutHandler::setArtifactParameterOverPost);
                map.from(serverProperties.getArtifactParameterName()).whenHasText().to(singleSignOutHandler::setArtifactParameterName);
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
    public void init(final FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        /**
         * <p>Workaround for now for the fact that Spring Security will fail since it doesn't call {@link #init(javax.servlet.FilterConfig)}.</p>
         * <p>Ultimately we need to allow deployers to actually inject their fully-initialized {@link org.jasig.cas.client.session.SingleSignOutHandler}.</p>
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
    public void destroy() {
        // nothing to do
    }

    public void setSessionMappingStorage(SessionMappingStorage sessionMappingStorage) {
        this.sessionMappingStorage = sessionMappingStorage;
    }

    public void setEagerlyCreateSessions(boolean eagerlyCreateSessions) {
        this.eagerlyCreateSessions = eagerlyCreateSessions;
    }

}
