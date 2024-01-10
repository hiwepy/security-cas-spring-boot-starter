package org.springframework.security.boot.cas;

import org.jasig.cas.client.util.AbstractConfigurationFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;

public abstract class AbstractCasRoutingFilter extends AbstractConfigurationFilter {

    private final SecurityCasAuthcProperties authcProperties;

    public AbstractCasRoutingFilter(SecurityCasAuthcProperties authcProperties) {
        this.authcProperties = authcProperties;
    }
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

    protected final String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        String artifactParameterName = serverProperties.getValidationType().getProtocol().getArtifactParameterName();
        String serviceParameterName = serverProperties.getValidationType().getProtocol().getServiceParameterName();
        return CommonUtils.constructServiceUrl(request, response, serverProperties.getServiceUrl(), this.getServerName(serverProperties),
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
        return CommonUtils.safeGetParameter(request, artifactParameterName, Arrays.asList(artifactParameterName));
    }

    /**
     * Note that trailing slashes should not be used in the serverName.  As a convenience for this common misconfiguration, we strip them from the provided
     * value.
     *
     * @param serverName the serverName. If this method is called, this should not be null.  This AND service should not be both configured.
     */
    protected final String getServerName(SecurityCasServerProperties serverProperties) {
        String serverName = serverProperties.getServiceUrl();
        if (serverName != null && serverName.endsWith("/")) {
            serverName = serverName.substring(0, serverName.length() - 1);
            logger.info("Eliminated extra slash from serverName [{}].  It is now [{}]", serverProperties.getServiceUrl(), serverName);
        }
        return serverName;
    }

}
