package org.springframework.security.boot.cas;

import org.apereo.cas.client.util.CommonUtils;
import org.apereo.cas.client.util.WebUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.RequestContextHolderUtils;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
/**
 * CasAuthenticationRoutingEntryPoint.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class CasAuthenticationRoutingEntryPoint extends CasAuthenticationEntryPoint {

    private final SecurityCasAuthcProperties authcProperties;

    public CasAuthenticationRoutingEntryPoint(SecurityCasAuthcProperties authcProperties) {
        super();
        this.authcProperties = authcProperties;
    }

    @Override
    /**
     * <p>After properties set.</p>
     */
    public void afterPropertiesSet() {
    }

    /**
     * Constructs a new Service Url. The default implementation relies on the CAS client
     * to do the bulk of the work.
     * @param request the HttpServletRequest
     * @param response the HttpServlet Response
     * @return the constructed service url. CANNOT be NULL.
     */
    @Override
    protected String createServiceUrl(final HttpServletRequest request,
                                      final HttpServletResponse response) {

        if (Objects.isNull(RequestContextHolder.getRequestAttributes())){
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        }
        // 1. Retrieve the matching CasServerProperties for the request
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        String artifactParameterName = serverProperties.getValidationType().getProtocol().getArtifactParameterName();
        String serviceParameterName = serverProperties.getValidationType().getProtocol().getServiceParameterName();
        return WebUtils.constructServiceUrl(request, response, serverProperties.getServiceUrl(), CasUrlUtils.getServerName(serverProperties),
                serviceParameterName, artifactParameterName, serverProperties.isEncodeServiceUrl());
    }

    /**
     * Constructs the Url for Redirection to the CAS server. Default implementation relies
     * on the CAS client to do the bulk of the work.
     *
     * @param serviceUrl the service url that should be included.
     * @return the redirect url. CANNOT be NULL.
     */
    @Override
    /**
     * <p>Creates a new redirect url.</p>
     * @param serviceUrl
     * @return the create redirect url
     */
    protected String createRedirectUrl(final String serviceUrl) {
        // 1. 根据referer获取TicketValidator
        HttpServletRequest request = RequestContextHolderUtils.getHttpServletRequest();
        if (Objects.isNull(request)) {
            return super.createRedirectUrl(serviceUrl);
        }
        // 2. Retrieve the matching CasServerProperties for the request
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        // 3. 构建重定向URL
        String loginUrl = CasUrlUtils.constructLoginRedirectUrl(serverProperties);
        return CommonUtils.constructRedirectUrl(loginUrl,
                serverProperties.getValidationType().getProtocol().getServiceParameterName(), serviceUrl,
                serverProperties.getRenew(), false);
    }

}
