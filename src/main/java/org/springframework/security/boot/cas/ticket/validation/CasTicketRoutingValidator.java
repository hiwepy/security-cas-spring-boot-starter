package org.springframework.security.boot.cas.ticket.validation;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.client.validation.Assertion;
import org.apereo.cas.client.validation.TicketValidationException;
import org.apereo.cas.client.validation.TicketValidator;
import org.springframework.http.HttpHeaders;
import org.springframework.security.boot.SecurityCasAuthcProperties;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.RequestContextHolderUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CasTicketRoutingValidator.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
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
            if (!StringUtils.hasText(serverProperties.getServiceReferer())
                    || ticketValidatorByReferer.containsKey(serverProperties.getServiceReferer())) {
                continue;
            }
            try {
                URL url = new URL(serverProperties.getServiceReferer());
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
            if (!StringUtils.hasText(serverProperties.getServerTag())
                    || ticketValidatorByTag.containsKey(serverProperties.getServerTag())) {
                continue;
            }
            try {
                ticketValidatorByTag.put(serverProperties.getServerTag(), this.ticketValidatorConfig.retrieveTicketValidator(serverProperties));
            } catch (Exception e) {
                log.error("initTicketValidatorByTag error", e);
                // ignore
            }
        }
    }

    @Override
    /**
     * <p>Validate.</p>
     * @param ticket
     * @param service
     * @return the validate
     */
    public Assertion validate(String ticket, String service) throws TicketValidationException {
        // 1. 根据referer获取TicketValidator
        HttpServletRequest request = RequestContextHolderUtils.getHttpServletRequest();
        return this.getTicketValidatorByRequest(request).validate(ticket, service);
    }

    /**
     * <p>Validate.</p>
     * @param request
     * @param ticket
     * @param service
     * @return the validate
     */
    public Assertion validate(HttpServletRequest request, String ticket, String service) throws TicketValidationException {
        return this.getTicketValidatorByRequest(request).validate(ticket, service);
    }

    /**
     * <p>Returns the ticket validator by request.</p>
     * @param request
     * @return the get ticket validator by request
     */
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
                log.error("get TicketValidator error", e);
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
                log.error("get TicketValidator error", e);
                // ignore
            }
        }
        log.debug("Using Default TicketValidator: " + this.getDefaultTicketValidator().getClass().getName());
        return this.getDefaultTicketValidator();
    }

    /**
     * <p>Returns the default ticket validator.</p>
     * @return the get default ticket validator
     */
    public TicketValidator getDefaultTicketValidator() {
        return defaultTicketValidator;
    }

    /**
     * <p>Returns the ticket validator by referer.</p>
     * @return the get ticket validator by referer
     */
    public Map<String, TicketValidator> getTicketValidatorByReferer() {
        return ticketValidatorByReferer;
    }

    /**
     * <p>Returns the ticket validator by tag.</p>
     * @return the get ticket validator by tag
     */
    public Map<String, TicketValidator> getTicketValidatorByTag() {
        return ticketValidatorByTag;
    }

}