package org.springframework.security.boot.cas;

import org.jasig.cas.client.validation.*;
import org.springframework.biz.utils.WebRequestUtils;
import org.springframework.biz.web.servlet.support.RequestContextUtils;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.SecurityCasServerProperties;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class MultiCasServerTicketValidator implements TicketValidator {

    public static final String DEFAULT_CAS_SERVICE_TAG_PARAMETER = "tag";
    /**
     * Whether Multi Cas Server Mode is enabled.
     */
    private boolean multiServer = false;
    /**
     * Specifies the name of the request parameter on where to find the multiServer (i.e. tag).
     */
    private String multiServerParameterName = DEFAULT_CAS_SERVICE_TAG_PARAMETER;

    private List<SecurityCasServerProperties> multiServers = new ArrayList<>();

    private TicketValidator defaultTicketValidator;
    private Map<String, TicketValidator> ticketValidatorByReferer;
    private Map<String, TicketValidator> ticketValidatorByTag;

    public MultiCasServerTicketValidator (boolean multiServer,
                                          String multiServerParameterName,
                                          TicketValidator defaultTicketValidator,
                                          List<SecurityCasServerProperties> multiServers) {
        this.defaultTicketValidator = defaultTicketValidator;
        this.initTicketValidatorByReferer(multiServers);
        this.initTicketValidatorByTag(multiServers);
    }

    private void initTicketValidatorByReferer(List<SecurityCasServerProperties> multiServers) {
        if (Objects.isNull(multiServers)) {
            return;
        }
        multiServers.stream().map(SecurityCasServerProperties::getServerUrlPrefix).forEach(referer -> {
            try {
                URL url = new URL(referer);
                this.ticketValidatorByReferer.put(url.getHost(), defaultTicketValidator);
            } catch (Exception e) {
                // ignore
            }
        }
        multiServers.forEach((referer, ticketValidator) -> {
            try {
                URL url = new URL(referer);
                this.ticketValidatorByReferer.put(url.getHost(), ticketValidator);
            } catch (Exception e) {
                // ignore
            }
        });
    }

    private void initTicketValidatorByTag(List<SecurityCasServerProperties> multiServers) {
        if (Objects.isNull(multiServers)) {
            return;
        }
        this.ticketValidatorByTag.forEach((tag, ticketValidator) -> {
            this.ticketValidatorByTag.put(tag, ticketValidator);
        });
    }


    @Override
    public Assertion validate(String ticket, String service) throws TicketValidationException {
        // 1. 根据referer获取TicketValidator
        HttpServletRequest request = WebUtils.getHttpServletRequest();
        if (Objects.isNull(request)) {
           return this.getDefaultTicketValidator().validate(ticket, service);
        }
        return null;
    }

    public void setDefaultTicketValidator(TicketValidator defaultTicketValidator) {
        this.defaultTicketValidator = defaultTicketValidator;
    }

    public TicketValidator getDefaultTicketValidator() {
        return defaultTicketValidator;
    }

    public void setTicketValidatorByReferer(Map<String, TicketValidator> ticketValidatorByReferer) {
        this.ticketValidatorByReferer = ticketValidatorByReferer;
    }

    public Map<String, TicketValidator> getTicketValidatorByReferer() {
        return ticketValidatorByReferer;
    }

    public void setTicketValidatorByTag(Map<String, TicketValidator> ticketValidatorByTag) {
        this.ticketValidatorByTag = ticketValidatorByTag;
    }

    public Map<String, TicketValidator> getTicketValidatorByTag() {
        return ticketValidatorByTag;
    }

}