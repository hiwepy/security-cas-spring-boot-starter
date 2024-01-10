package org.springframework.security.boot.cas.ticket.validation;

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
public class CasTicketRoutingValidator implements TicketValidator {

    private final SecurityCasAuthcProperties authcProperties;
    private final CasTicketValidatorConfiguration ticketValidatorConfig;
    private final TicketValidator defaultTicketValidator;
    private final Map<String, TicketValidator> ticketValidatorByReferer = new ConcurrentHashMap<>();
    private final Map<String, TicketValidator> ticketValidatorByTag = new ConcurrentHashMap<>();

    public CasTicketRoutingValidator(SecurityCasAuthcProperties authcProperties,
                                     CasTicketValidatorConfiguration ticketValidatorConfig) {
        this.authcProperties = authcProperties;
        this.ticketValidatorConfig = ticketValidatorConfig;
        this.defaultTicketValidator = ticketValidatorConfig.retrieveTicketValidator(CollectionUtils.firstElement(authcProperties.getServers()));
        this.initTicketValidatorByReferer(authcProperties.getServers());
        this.initTicketValidatorByTag(authcProperties.getServers());
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
            if (!StringUtils.hasText(serverProperties.getServerName())
                    || ticketValidatorByTag.containsKey(serverProperties.getServerName())) {
                continue;
            }
            try {
                ticketValidatorByTag.put(serverProperties.getServerName(), this.ticketValidatorConfig.retrieveTicketValidator(serverProperties));
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
        return this.getTicketValidatorByRequest(request).validate(ticket, service);
    }

    public Assertion validate(HttpServletRequest request, String ticket, String service) throws TicketValidationException {
        return this.getTicketValidatorByRequest(request).validate(ticket, service);
    }

    public TicketValidator getTicketValidatorByRequest(HttpServletRequest request) {
        if (Objects.isNull(request)) {
            log.debug("Using Default TicketValidator: " + this.getDefaultTicketValidator().getClass().getName());
            return this.getDefaultTicketValidator();
        }
        // 2. 根据serverTag获取TicketValidator
        String tag = request.getParameter(authcProperties.getServerTagParameterName());
        if (StringUtils.hasText(tag)) {
            log.debug("Using Tag parameter: " + tag);
            try {
                TicketValidator ticketValidator = this.getTicketValidatorByTag().get(tag);
                if (Objects.nonNull(ticketValidator)) {
                    return ticketValidator;
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
                    return ticketValidator;
                }
            } catch (Exception e) {
                log.error("validate error", e);
                // ignore
            }
        }
        log.debug("Using Default TicketValidator: " + this.getDefaultTicketValidator().getClass().getName());
        return this.getDefaultTicketValidator();
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