package org.springframework.security.boot.cas;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

public class CasAuthenticationRoutingFilter extends CasAuthenticationFilter {

    /**
     * The last portion of the receptor url, i.e. /proxy/receptor
     */
    private RequestMatcher proxyReceptorMatcher;

    /**
     * The backing storage to store ProxyGrantingTicket requests.
     */
    private ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider;
    private final SecurityCasAuthcProperties authcProperties;

    public CasAuthenticationRoutingFilter(SecurityCasAuthcProperties authcProperties) {
        super();
        this.authcProperties = authcProperties;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (Objects.isNull(RequestContextHolder.getRequestAttributes())){
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        }
        super.doFilter(request, response, chain);
    }

    /**
     * Performs actual authentication.
     * <p>
     * The implementation should do one of the following:
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating
     * successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress.
     * Before returning, the implementation should perform any additional work required to
     * complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * </ol>
     *
     * @param request from which to extract parameters and perform the authentication
     * @param response the response, which may be needed if the implementation has to do a
     * redirect as part of a multi-stage authentication process (such as OpenID).
     *
     * @return the authenticated user token, or null if authentication is incomplete.
     *
     * @throws AuthenticationException if authentication fails.
     * @throws IOException if an I/O problem occurred during authentication.
     */
    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request,
                                                final HttpServletResponse response) throws AuthenticationException, IOException {

        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        ProxyGrantingTicketStorage proxyGrantingTicketStorage = this.proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties);
        // if the request is a proxy request process it and return null to indicate the
        // request has been processed
        if (proxyReceptorRequest(request)) {
            logger.debug("Responding to proxy receptor request");
            CommonUtils.readAndRespondToProxyReceptorRequest(request, response, proxyGrantingTicketStorage);
            return null;
        }

        final boolean serviceTicketRequest = this.serviceTicketRequest(request, response);
        final String username = serviceTicketRequest ? CAS_STATEFUL_IDENTIFIER : CAS_STATELESS_IDENTIFIER;
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
    protected boolean proxyReceptorConfigured(final HttpServletRequest request) {
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        if(Objects.isNull(serverProperties)){
            return Boolean.FALSE;
        }
        ProxyGrantingTicketStorage proxyGrantingTicketStorage = this.proxyGrantingTicketStorageProvider.getProxyGrantingTicketStorage(serverProperties);
        final boolean result = proxyGrantingTicketStorage != null && proxyReceptorMatcher != null;
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
        final boolean result = proxyReceptorConfigured(request) && proxyReceptorMatcher.matches(request);
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

    public void setProxyReceptorUrl2(final String proxyReceptorUrl) {
        super.setProxyReceptorUrl(proxyReceptorUrl);
        this.proxyReceptorMatcher = new AntPathRequestMatcher("/**" + proxyReceptorUrl);
    }

    public void setProxyGrantingTicketStorageProvider(ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
        this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider;
    }
}
