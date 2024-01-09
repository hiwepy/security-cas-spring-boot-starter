package org.springframework.security.boot.cas;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

public class CasAuthenticationExtEntryPoint extends CasAuthenticationEntryPoint {

    private final SecurityCasAuthcProperties authcProperties;

    public CasAuthenticationExtEntryPoint(SecurityCasAuthcProperties authcProperties) {
        super();
        this.authcProperties = authcProperties;
    }

    @Override
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
        // 1. 获取请求匹配的CasServerProperties
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);

        return CommonUtils.constructServiceUrl(null, response,
                serverProperties.getServiceUrl(), null,
                serverProperties.getArtifactParameterName(),
                this.getEncodeServiceUrlWithSessionId());
    }

    /**
     * Constructs the Url for Redirection to the CAS server. Default implementation relies
     * on the CAS client to do the bulk of the work.
     *
     * @param serviceUrl the service url that should be included.
     * @return the redirect url. CANNOT be NULL.
     */
    @Override
    protected String createRedirectUrl(final String serviceUrl) {
        // 1. 根据referer获取TicketValidator
        HttpServletRequest request = WebUtils.getHttpServletRequest();
        if (Objects.isNull(request)) {
            return super.createRedirectUrl(serviceUrl);
        }
        // 2. 获取请求匹配的CasServerProperties
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        // 3. 构建重定向URL
        String loginUrl = CasUrlUtils.constructLoginRedirectUrl(serverProperties);
        return CommonUtils.constructRedirectUrl(loginUrl,
                serverProperties.getServiceParameterName(), serviceUrl,
                serverProperties.getRenew(), false);
    }

}
