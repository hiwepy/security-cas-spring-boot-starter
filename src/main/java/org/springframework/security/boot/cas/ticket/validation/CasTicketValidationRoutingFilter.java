package org.springframework.security.boot.cas.ticket.validation;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.AbstractTicketValidationFilter;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.http.HttpHeaders;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.AbstractCasRoutingFilter;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class CasTicketValidationRoutingFilter extends AbstractCasRoutingFilter {

    /** The TicketValidator we will use to validate tickets. */
    private final TicketValidator ticketValidator;
    private final SecurityCasAuthcProperties authcProperties;
    private final ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider;
    private final CasTicketValidationFilterConfiguration ticketValidationFilterConfig;
    private final AbstractTicketValidationFilter defaultTicketValidationFilter;
    private final Map<String, AbstractTicketValidationFilter> ticketValidationFilterByReferer = new ConcurrentHashMap<>();
    private final Map<String, AbstractTicketValidationFilter> ticketValidationFilterByTag = new ConcurrentHashMap<>();

    public CasTicketValidationRoutingFilter(SecurityCasAuthcProperties authcProperties,
                                            CasTicketValidationFilterConfiguration ticketValidationFilterConfig,
                                            TicketValidator ticketValidator,
                                            ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
        super(authcProperties);
        this.authcProperties = authcProperties;
        this.ticketValidationFilterConfig = ticketValidationFilterConfig;
        this.ticketValidator = ticketValidator;
        this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
        this.defaultTicketValidationFilter = ticketValidationFilterConfig.retrieveTicketValidationFilter(ticketValidator,
                CollectionUtils.firstElement(authcProperties.getServers()));
        this.initTicketValidationFilterByReferer(authcProperties.getServers());
        this.initTicketValidationFilterByTag(authcProperties.getServers());
    }

    private void initTicketValidationFilterByReferer(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getReferer())
                    || ticketValidationFilterByReferer.containsKey(serverProperties.getReferer())) {
                continue;
            }
            try {
                URL url = new URL(serverProperties.getReferer());
                ticketValidationFilterByReferer.put(url.getHost(),
                        this.ticketValidationFilterConfig.retrieveTicketValidationFilter(ticketValidator, serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByReferer error", e);
                // ignore
            }
        }
    }

    private void initTicketValidationFilterByTag(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getServerTag())
                    || ticketValidationFilterByTag.containsKey(serverProperties.getServerTag())) {
                continue;
            }
            try {
                ticketValidationFilterByTag.put(serverProperties.getServerTag(),
                        this.ticketValidationFilterConfig.retrieveTicketValidationFilter(ticketValidator, serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByTag error", e);
                // ignore
            }
        }
    }

    @Override
    public void init() {
        super.init();
        CommonUtils.assertNotNull(this.ticketValidator, "ticketValidator cannot be null.");
    }

    /**
     * This processes the ProxyReceptor request before the ticket validation code executes.
     */
    protected boolean preFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                                      final FilterChain filterChain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final String requestUri = request.getRequestURI();

        if (CommonUtils.isEmpty(authcProperties.getProxyReceptorUrl()) || !requestUri.endsWith(authcProperties.getProxyReceptorUrl())) {
            return Boolean.TRUE;
        }

        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        if(Objects.isNull(serverProperties)){
            return Boolean.TRUE;
        }

        try {
            ProxyGrantingTicketStorage proxyGrantingTicketStorage = getProxyGrantingTicketStorageProvider().getProxyGrantingTicketStorage(serverProperties);
            CommonUtils.readAndRespondToProxyReceptorRequest(request, response, proxyGrantingTicketStorage);
        } catch (final RuntimeException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return Boolean.FALSE;
    }

    @Override
    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                               final FilterChain filterChain) throws IOException, ServletException {

        if (!preFilter(servletRequest, servletResponse, filterChain)) {
            return;
        }

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        this.getTicketValidationFilterByRequest(request).doFilter(request, response, filterChain);

    }

    public AbstractTicketValidationFilter getTicketValidationFilterByRequest(HttpServletRequest request) {
        if (Objects.isNull(request)) {
            log.debug("Using Default TicketValidationFilter: " + this.getDefaultTicketValidationFilter().getClass().getName());
            return this.getDefaultTicketValidationFilter();
        }
        // 2. 根据serverTag获取TicketValidator
        String tag = request.getParameter(authcProperties.getServerTagParameterName());
        if (StringUtils.hasText(tag)) {
            log.debug("Using Tag parameter: " + tag);
            try {
                AbstractTicketValidationFilter ticketValidationFilter = this.getTicketValidationFilterByTag().get(tag);
                if (Objects.nonNull(ticketValidationFilter)) {
                    return ticketValidationFilter;
                }
            } catch (Exception e) {
                log.error("Get TicketValidationFilter error", e);
                // ignore
            }
        }
        // 3. 根据referer获取TicketValidator
        String referer = request.getHeader(HttpHeaders.REFERER);
        if (StringUtils.hasText(referer)) {
            log.debug("Using Referer header: " + referer);
            try {
                URL url = new URL(referer);
                AbstractTicketValidationFilter ticketValidationFilter = this.getTicketValidationFilterByReferer().get(url.getHost());
                if (Objects.nonNull(ticketValidationFilter)) {
                    return ticketValidationFilter;
                }
            } catch (Exception e) {
                log.error("Get TicketValidationFilter error", e);
                // ignore
            }
        }
        log.debug("Using Default TicketValidationFilter: " + this.getDefaultTicketValidationFilter().getClass().getName());
        return this.getDefaultTicketValidationFilter();
    }

    public ProxyGrantingTicketStorageProvider getProxyGrantingTicketStorageProvider() {
        return proxyGrantingTicketStorageProvider;
    }

    public AbstractTicketValidationFilter getDefaultTicketValidationFilter() {
        return defaultTicketValidationFilter;
    }

    public Map<String, AbstractTicketValidationFilter> getTicketValidationFilterByReferer() {
        return ticketValidationFilterByReferer;
    }

    public Map<String, AbstractTicketValidationFilter> getTicketValidationFilterByTag() {
        return ticketValidationFilterByTag;
    }

    public TicketValidator getTicketValidator() {
        return ticketValidator;
    }

}
