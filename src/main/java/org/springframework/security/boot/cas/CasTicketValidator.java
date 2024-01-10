package org.springframework.security.boot.cas;

import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.http.HttpHeaders;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class CasTicketValidator implements TicketValidator {

    private SecurityCasAuthcProperties authcProperties;
    private TicketValidator defaultTicketValidator;
    private Map<String, TicketValidator> ticketValidatorByReferer = new ConcurrentHashMap<>();
    private Map<String, TicketValidator> ticketValidatorByTag = new ConcurrentHashMap<>();
    private CasTicketValidatorConfiguration ticketValidatorConfig;

    public CasTicketValidator(SecurityCasAuthcProperties casProperties,
                              ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
        this.authcProperties = casProperties;
        this.ticketValidatorConfig = new CasTicketValidatorConfiguration(proxyGrantingTicketStorageProvider);
        this.ticketValidatorConfig.setAcceptAnyProxy(casProperties.isAcceptAnyProxy());
        this.ticketValidatorConfig.setProxyReceptorUrl(casProperties.getProxyReceptorUrl());
        this.ticketValidatorConfig.setProxyCallbackUrl(casProperties.getProxyCallbackUrl());
        this.defaultTicketValidator = ticketValidatorConfig.retrieveTicketValidator(CollectionUtils.firstElement(casProperties.getServers()));
        this.initTicketValidatorByReferer(casProperties.getServers());
        this.initTicketValidatorByTag(casProperties.getServers());
    }

    private void initTicketValidatorByReferer(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getReferer())
                    || ticketValidatorByReferer.containsKey(serverProperties.getReferer())) {
                continue;
            }
            try {
                URL url = new URL(serverProperties.getReferer());
                ticketValidatorByReferer.put(url.getHost(), this.ticketValidatorConfig.retrieveTicketValidator(serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByReferer error", e);
                // ignore
            }
        }
    }

    private void initTicketValidatorByTag(List<SecurityCasServerProperties> servers) {
        if (Objects.isNull(servers)) {
            return;
        }
        for (SecurityCasServerProperties serverProperties : servers) {
            if (!StringUtils.hasText(serverProperties.getName())
                    || ticketValidatorByTag.containsKey(serverProperties.getName())) {
                continue;
            }
            try {
                ticketValidatorByTag.put(serverProperties.getName(), this.ticketValidatorConfig.retrieveTicketValidator(serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByTag error", e);
                // ignore
            }
        }
    }

    @Override
    public Assertion validate(String ticket, String service) throws TicketValidationException {
        // 1. 根据referer获取TicketValidator
        HttpServletRequest request = WebUtils.getHttpServletRequest();
        if (Objects.isNull(request)) {
           log.debug("Using Default TicketValidator: " + this.getDefaultTicketValidator().getClass().getName());
           return this.getDefaultTicketValidator().validate(ticket, service);
        }
        // 2. 根据serverTag获取TicketValidator
        String tag = request.getParameter(authcProperties.getServerTagParameterName());
        if (StringUtils.hasText(tag)) {
            log.debug("Using Tag parameter: " + tag);
            try {
                TicketValidator ticketValidator = this.getTicketValidatorByTag().get(tag);
                if (Objects.nonNull(ticketValidator)) {
                    return ticketValidator.validate(ticket, service);
                }
            } catch (Exception e) {
                log.error("validate error", e);
                // ignore
            }
        }
        // 3. 根据referer获取TicketValidator
        String referer = request.getHeader(HttpHeaders.REFERER);
        if (StringUtils.hasText(referer)) {
            log.debug("Using Referer header: " + referer);
            try {
                URL url = new URL(referer);
                TicketValidator ticketValidator = this.getTicketValidatorByReferer().get(url.getHost());
                if (Objects.nonNull(ticketValidator)) {
                    return ticketValidator.validate(ticket, service);
                }
            } catch (Exception e) {
                log.error("validate error", e);
                // ignore
            }
        }
        log.debug("Using Default TicketValidator: " + this.getDefaultTicketValidator().getClass().getName());
        return this.getDefaultTicketValidator().validate(ticket, service);
    }

    public void setDefaultTicketValidator(TicketValidator defaultTicketValidator) {
        this.defaultTicketValidator = defaultTicketValidator;
    }

    public TicketValidator getDefaultTicketValidator() {
        return defaultTicketValidator;
    }
    public Map<String, TicketValidator> getTicketValidatorByReferer() {
        return ticketValidatorByReferer;
    }

    public Map<String, TicketValidator> getTicketValidatorByTag() {
        return ticketValidatorByTag;
    }

}