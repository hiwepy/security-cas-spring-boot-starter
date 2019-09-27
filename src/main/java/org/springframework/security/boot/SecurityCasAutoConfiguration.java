package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.boot.cas.rememberme.CasRememberMeServices;
import org.springframework.security.boot.cas.userdetails.CasAuthenticationUserDetailsService;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityCasAutoConfiguration {

	@Autowired
	private SecurityCasProperties casProperties;
	// @Autowired
	// private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;

	@Bean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new SessionFixationProtectionStrategy();
	}

	@Bean
	public RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
		return new CasRememberMeServices(null, userDetailsService);
	}

	@Bean
	public ServiceProperties serviceProperties() {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setArtifactParameter(casProperties.getArtifactParameterName());
		// serviceProperties.setAuthenticateAllArtifacts(authenticateAllArtifacts);
		serviceProperties.setSendRenew(casProperties.isRenew());
		serviceProperties.setService(casProperties.getService());
		serviceProperties.setServiceParameter(casProperties.getServiceParameterName());
		return serviceProperties;
	}

	@Bean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource(
			ServiceProperties serviceProperties) {
		return new ServiceAuthenticationDetailsSource(serviceProperties);
	}
	
	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint(ServiceProperties serviceProperties) {

		CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

		entryPoint.setEncodeServiceUrlWithSessionId(casProperties.isEncodeServiceUrlWithSessionId());
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties,
				serverProperties.getServlet().getContextPath(), casProperties.getServerCallbackUrl()));
		entryPoint.setServiceProperties(serviceProperties);

		return entryPoint;
	}

	/*
	 * 指定cas校验器
	 */
	@Bean
	@ConditionalOnMissingBean
	public TicketValidator ticketValidator() {
		// Cas20ServiceTicketValidator ticketValidator
		return new Cas30ServiceTicketValidator(casProperties.getCasServerUrlPrefix());
	}

	@Bean
	public CasAuthenticationProvider casAuthenticationProvider(
			CasAuthenticationUserDetailsService userDetailsService,
			ServiceProperties serviceProperties, TicketValidator ticketValidator) {

		CasAuthenticationProvider provider = new CasAuthenticationProvider();
		provider.setKey("casProvider");
		provider.setServiceProperties(serviceProperties);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(userDetailsService);

		return provider;
	}

}
