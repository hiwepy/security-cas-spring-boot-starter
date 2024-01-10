package org.springframework.security.boot.cas.ticket.validation;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.AbstractTicketValidationFilter;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class CasTicketValidationRoutingFilter extends AbstractCasFilter {

    /** The TicketValidator we will use to validate tickets. */
    private CasTicketRoutingValidator ticketValidator;
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
        super(Protocol.CAS3);
        this.authcProperties = authcProperties;
        this.ticketValidationFilterConfig = ticketValidationFilterConfig;
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
                ticketValidationFilterByReferer.put(url.getHost(), this.ticketFilterConfig.retrieveTicketValidationFilter(serverProperties));
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
            if (!StringUtils.hasText(serverProperties.getServerName())
                    || ticketValidationFilterByTag.containsKey(serverProperties.getServerName())) {
                continue;
            }
            try {
                ticketValidationFilterByTag.put(serverProperties.getServerName(), this.ticketFilterConfig.retrieveTicketValidationFilter(serverProperties));
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

    @Override
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
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


    /**
     * Template method that gets executed if ticket validation succeeds.  Override if you want additional behavior to occur
     * if ticket validation succeeds.  This method is called after all ValidationFilter processing required for a successful authentication
     * occurs.
     *
     * @param request the HttpServletRequest.
     * @param response the HttpServletResponse.
     * @param assertion the successful Assertion from the server.
     */
    protected void onSuccessfulValidation(final HttpServletRequest request, final HttpServletResponse response,
                                          final Assertion assertion) {
        // nothing to do here.
    }

    /**
     * Template method that gets executed if validation fails.  This method is called right after the exception is caught from the ticket validator
     * but before any of the processing of the exception occurs.
     *
     * @param request the HttpServletRequest.
     * @param response the HttpServletResponse.
     */
    protected void onFailedValidation(final HttpServletRequest request, final HttpServletResponse response) {
        // nothing to do here.
    }

    protected String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response, SecurityCasServerProperties serverProperties) {
        return CommonUtils.constructServiceUrl(request, response, this.service, this.serverName,
                this.protocol.getServiceParameterName(),
                this.protocol.getArtifactParameterName(), this.encodeServiceUrl);
    }

    @Override
    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                               final FilterChain filterChain) throws IOException, ServletException {

        if (!preFilter(servletRequest, servletResponse, filterChain)) {
            return;
        }

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;
        final String ticket = retrieveTicketFromRequest(request);

        if (CommonUtils.isNotBlank(ticket)) {
            logger.debug("Attempting to validate ticket: {}", ticket);

            SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);

            try {

                final Assertion assertion = this.ticketValidator.validate(request, ticket, constructServiceUrl(request, response, serverProperties));

                logger.debug("Successfully authenticated user: {}", assertion.getPrincipal().getName());

                request.setAttribute(serverProperties.getServerName() +  CONST_CAS_ASSERTION, assertion);

                if (serverProperties.isUseSession()) {
                    request.getSession().setAttribute(serverProperties.getServerName() + CONST_CAS_ASSERTION, assertion);
                }
                onSuccessfulValidation(request, response, assertion);

                if (serverProperties.isRedirectAfterValidation()) {
                    logger.debug("Redirecting after successful ticket validation.");
                    response.sendRedirect(constructServiceUrl(request, response));
                    return;
                }
            } catch (final TicketValidationException e) {
                logger.debug(e.getMessage(), e);

                onFailedValidation(request, response);

                if (serverProperties.isExceptionOnValidationFailure()) {
                    throw new ServletException(e);
                }

                response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());

                return;
            }
        }

        filterChain.doFilter(request, response);

    }

    public void setTicketValidator(CasTicketRoutingValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    public void setProxyGrantingTicketStorageProvider(ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
        this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
    }

    public ProxyGrantingTicketStorageProvider getProxyGrantingTicketStorageProvider() {
        return proxyGrantingTicketStorageProvider;
    }

}
