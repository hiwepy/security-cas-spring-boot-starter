package org.springframework.security.cas.web.authentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.cas.ServiceProperties;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Slf4j
public class ServiceAuthenticationDetailsExtSource extends ServiceAuthenticationDetailsSource {

    private final Map<String, Pattern> artifactPatternMap = new ConcurrentHashMap<>();
    private SecurityCasAuthcProperties authcProperties;

    public ServiceAuthenticationDetailsExtSource(SecurityCasAuthcProperties authcProperties) {
        super(new ServiceProperties());
        this.authcProperties = authcProperties;
        this.initArtifactPatternMap(authcProperties.getServers());
    }

    private void initArtifactPatternMap(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getServerUrlPrefix())
                    || artifactPatternMap.containsKey(serverProperties.getServerUrlPrefix())) {
                continue;
            }
            try {
                artifactPatternMap.put(serverProperties.getServerUrlPrefix(), DefaultServiceAuthenticationDetails
                        .createArtifactPattern(serverProperties.getValidationType().getProtocol().getArtifactParameterName()));
            } catch (Exception e) {
                log.error("initArtifactPatternMap error", e);
                // ignore
            }
        }
    }

    @Override
    public ServiceAuthenticationDetails buildDetails(HttpServletRequest context) {
        HttpServletRequest request = WebUtils.getHttpServletRequest();
        SecurityCasServerProperties serverProperties = authcProperties.getByRequest(request);
        Pattern artifactPattern = this.artifactPatternMap.get(serverProperties.getServerUrlPrefix());
        try {
            return new DefaultServiceAuthenticationDetails(serverProperties.getServiceUrl(), context, artifactPattern);
        }
        catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

}
