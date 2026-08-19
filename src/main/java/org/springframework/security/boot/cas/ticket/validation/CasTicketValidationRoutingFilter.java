package org.springframework.security.boot.cas.ticket.validation;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.client.proxy.ProxyGrantingTicketStorage;
import org.apereo.cas.client.util.CommonUtils;
import org.apereo.cas.client.util.WebUtils;
import org.apereo.cas.client.validation.AbstractTicketValidationFilter;
import org.apereo.cas.client.validation.TicketValidator;
import org.springframework.http.HttpHeaders;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.AbstractCasRoutingFilter;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CasTicketValidationRoutingFilter.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
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

    /**
     * Constructs a new cas ticket validation routing filter instance.
     *
     * @param authcProperties the authc properties
     * @param ticketValidationFilterConfig the ticket validation filter config
     * @param ticketValidator the ticket validator
     * @param proxyGrantingTicketStorageProvider the proxy granting ticket storage provider
     */
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
            if (!StringUtils.hasText(serverProperties.getServiceReferer())
                    || ticketValidationFilterByReferer.containsKey(serverProperties.getServiceReferer())) {
                continue;
            }
            try {
                URL url = new URL(serverProperties.getServiceReferer());
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
    /**
     * <p>Initializes the init.</p>
     */
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
            WebUtils.readAndRespondToProxyReceptorRequest(request, response, proxyGrantingTicketStorage);
        } catch (final RuntimeException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }

        return Boolean.FALSE;
    }

    /**
     * do Filter.
     *
     * @param servletRequest the servlet request
     * @param servletResponse the servlet response
     * @param filterChain the filter chain
     * @throws IOException if an error occurs
     * @throws ServletException if an error occurs
     */
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

    /**
     * <p>Returns the ticket validation filter by request.</p>
     * @param request
     * @return the get ticket validation filter by request
     */
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

    /**
     * <p>Returns the proxy granting ticket storage provider.</p>
     * @return the get proxy granting ticket storage provider
     */
    public ProxyGrantingTicketStorageProvider getProxyGrantingTicketStorageProvider() {
        return proxyGrantingTicketStorageProvider;
    }

    /**
     * <p>Returns the default ticket validation filter.</p>
     * @return the get default ticket validation filter
     */
    public AbstractTicketValidationFilter getDefaultTicketValidationFilter() {
        return defaultTicketValidationFilter;
    }

    /**
     * <p>Returns the ticket validation filter by referer.</p>
     * @return the get ticket validation filter by referer
     */
    public Map<String, AbstractTicketValidationFilter> getTicketValidationFilterByReferer() {
        return ticketValidationFilterByReferer;
    }

    /**
     * <p>Returns the ticket validation filter by tag.</p>
     * @return the get ticket validation filter by tag
     */
    public Map<String, AbstractTicketValidationFilter> getTicketValidationFilterByTag() {
        return ticketValidationFilterByTag;
    }

    /**
     * <p>Returns the ticket validator.</p>
     * @return the get ticket validator
     */
    public TicketValidator getTicketValidator() {
        return ticketValidator;
    }

}
