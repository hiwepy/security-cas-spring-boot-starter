package org.springframework.security.boot.cas;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CasAuthenticationExtFilter extends CasAuthenticationFilter {

    /**
     * The last portion of the receptor url, i.e. /proxy/receptor
     */
    private RequestMatcher proxyReceptorMatcher;

    /**
     * The backing storage to store ProxyGrantingTicket requests.
     */
    private ProxyGrantingTicketStorage proxyGrantingTicketStorage;

    public CasAuthenticationExtFilter() {
        super();
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request,
                                                final HttpServletResponse response) throws AuthenticationException,
            IOException {
        // if the request is a proxy request process it and return null to indicate the
        // request has been processed
        if (proxyReceptorRequest(request)) {
            logger.debug("Responding to proxy receptor request");
            CommonUtils.readAndRespondToProxyReceptorRequest(request, response,
                    this.proxyGrantingTicketStorage);
            return null;
        }

        final boolean serviceTicketRequest = this.serviceTicketRequest(request, response);
        final String username = serviceTicketRequest ? CAS_STATEFUL_IDENTIFIER
                : CAS_STATELESS_IDENTIFIER;
        String password = obtainArtifact(request);

        if (password == null) {
            logger.debug("Failed to obtain an artifact (cas ticket)");
            password = "";
        }

        final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username, password);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Determines if the {@link CasAuthenticationFilter} is configured to handle the proxy
     * receptor requests.
     *
     * @return
     */
    protected boolean proxyReceptorConfigured() {
        final boolean result = this.proxyGrantingTicketStorage != null
                && proxyReceptorMatcher != null;
        if (logger.isDebugEnabled()) {
            logger.debug("proxyReceptorConfigured = " + result);
        }
        return result;
    }

    /**
     * Indicates if the request is elgible to be processed as the proxy receptor.
     * @param request
     * @return
     */
    protected boolean proxyReceptorRequest(final HttpServletRequest request) {
        final boolean result = proxyReceptorConfigured()
                && proxyReceptorMatcher.matches(request);
        if (logger.isDebugEnabled()) {
            logger.debug("proxyReceptorRequest = " + result);
        }
        return result;
    }

    /**
     * Indicates if the request is elgible to process a service ticket. This method exists
     * for readability.
     * @param request
     * @param response
     * @return
     */
    protected boolean serviceTicketRequest(final HttpServletRequest request,
                                         final HttpServletResponse response) {
        boolean result = super.requiresAuthentication(request, response);
        if (logger.isDebugEnabled()) {
            logger.debug("serviceTicketRequest = " + result);
        }
        return result;
    }

    public void setProxyReceptorMatcher(RequestMatcher proxyReceptorMatcher) {
        super.setProxyReceptorUrl(proxyReceptorMatcher.toString());
        this.proxyReceptorMatcher = proxyReceptorMatcher;
    }

}
