package org.springframework.security.boot.cas;

import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apereo.cas.client.util.AbstractConfigurationFilter;
import org.apereo.cas.client.util.WebUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.CasUrlUtils;

import java.util.Arrays;
/**
 * AbstractCasRoutingFilter.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public abstract class AbstractCasRoutingFilter extends AbstractConfigurationFilter {

    private final SecurityCasAuthcProperties authcProperties;

    /**
     * Constructs a new abstract cas routing filter instance.
     *
     * @param authcProperties the authc properties
     */
    public AbstractCasRoutingFilter(SecurityCasAuthcProperties authcProperties) {
        this.authcProperties = authcProperties;
    }
    /**
     * init.
     *
     * @param filterConfig the filter config
     * @throws ServletException if an error occurs
     */
    @Override
    public final void init(final FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        if (!isIgnoreInitConfiguration()) {
            initInternal(filterConfig);
        }
        init();
    }
    /**
     * Initialization method.  Called by Filter's init method or by Spring.  Similar in concept to the InitializingBean interface's
     * afterPropertiesSet();
     */
    public void init() {

    }

    /** Controls the ordering of filter initialization and checking by defining a method that runs before the init.
     * @param filterConfig the original filter configuration.
     * @throws ServletException if there is a problem.
     *
     */
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
        // template method
    }

    /**
     * construct Service URL.
     *
     * @param request the request
     * @param response the response
     * @return the result
     */
    protected final String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        String artifactParameterName = serverProperties.getValidationType().getProtocol().getArtifactParameterName();
        String serviceParameterName = serverProperties.getValidationType().getProtocol().getServiceParameterName();
        return WebUtils.constructServiceUrl(request, response, serverProperties.getServiceUrl(), CasUrlUtils.getServerName(serverProperties),
                serviceParameterName, artifactParameterName, serverProperties.isEncodeServiceUrl());
    }

    /**
     * Template method to allow you to change how you retrieve the ticket.
     *
     * @param request the HTTP ServletRequest.  CANNOT be NULL.
     * @return the ticket if its found, null otherwise.
     */
    protected String retrieveTicketFromRequest(final HttpServletRequest request) {
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        String artifactParameterName = serverProperties.getValidationType().getProtocol().getArtifactParameterName();
        return WebUtils.safeGetParameter(request, artifactParameterName, Arrays.asList(artifactParameterName));
    }


}
