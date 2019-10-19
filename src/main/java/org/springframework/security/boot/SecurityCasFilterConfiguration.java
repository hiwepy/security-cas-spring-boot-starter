package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.CollectionUtils;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class, 
	SecurityCasAuthcProperties.class, ServerProperties.class })
public class SecurityCasFilterConfiguration {


	/**
	 * 	单点注销Session监听器
	 */
    @Bean
    public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListener(){
        ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> servletListenerRegistrationBean =
                new ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>();
        servletListenerRegistrationBean.setListener(new SingleSignOutHttpSessionListener());
        servletListenerRegistrationBean.setOrder(1);
        return servletListenerRegistrationBean;
    }
    
    /*
	 * 	CAS SignOut Filter
	 * 	该过滤器用于实现单点登出功能，单点退出配置，一定要放在其他filter之前
	 */
	@Bean
	public FilterRegistrationBean<SingleSignOutFilter> singleSignOutFilter(SecurityCasProperties casProperties,
			SecurityCasAuthcProperties casAuthcProperties, SessionMappingStorage sessionMappingStorage) {
		
		FilterRegistrationBean<SingleSignOutFilter> filterRegistration = new FilterRegistrationBean<SingleSignOutFilter>();
		filterRegistration.setFilter(new SingleSignOutFilter());
		filterRegistration.setEnabled(casProperties.isEnabled());
		
		if(StringUtils.hasText(casProperties.getArtifactParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_NAME.getName(), casProperties.getArtifactParameterName());
		}
		if(StringUtils.hasText(casProperties.getLogoutParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.LOGOUT_PARAMETER_NAME.getName(), casProperties.getLogoutParameterName());
		}
		if(StringUtils.hasText(casProperties.getRelayStateParameterName())) {	
			filterRegistration.addInitParameter(ConfigurationKeys.RELAY_STATE_PARAMETER_NAME.getName(), casProperties.getRelayStateParameterName());
		}
		filterRegistration.addInitParameter(ConfigurationKeys.CAS_SERVER_URL_PREFIX.getName(), casProperties.getPrefixUrl());
		filterRegistration.addInitParameter(ConfigurationKeys.ARTIFACT_PARAMETER_OVER_POST.getName(), String.valueOf(casProperties.isArtifactParameterOverPost()));
		filterRegistration.addInitParameter(ConfigurationKeys.EAGERLY_CREATE_SESSIONS.getName(), String.valueOf(casProperties.isEagerlyCreateSessions()));
		
		filterRegistration.addUrlPatterns(casAuthcProperties.getSsoPathPatterns());
		filterRegistration.setOrder(2);
		return filterRegistration;
	}
	
	/*
	 * 	CAS Assertion Thread Local Filter
	 * 	该过滤器使得可以通过org.jasig.cas.client.util.AssertionHolder来获取用户的登录名。
	 * 	比如AssertionHolder.getAssertion().getPrincipal().getName()。
	 * 	这个类把Assertion信息放在ThreadLocal变量中，这样应用程序不在web层也能够获取到当前登录信息
	 */
	@Bean
	public FilterRegistrationBean<AssertionThreadLocalFilter> assertionThreadLocalFilter(SecurityCasProperties casProperties,
			SecurityCasAuthcProperties casAuthcProperties) {
		FilterRegistrationBean<AssertionThreadLocalFilter> filterRegistration = new FilterRegistrationBean<AssertionThreadLocalFilter>();
		filterRegistration.setFilter(new AssertionThreadLocalFilter());
		filterRegistration.setEnabled(casProperties.isEnabled());
		filterRegistration.addUrlPatterns(casAuthcProperties.getAssertionPathPatterns());
		filterRegistration.setOrder(6);
		return filterRegistration;
	}
	
	
    @Bean("casLogoutSuccessHandler")
	public LogoutSuccessHandler logoutSuccessHandler(SecurityCasProperties casProperties) {
		return new ForwardLogoutSuccessHandler(casProperties.getLoginUrl());
	}
    
	@Bean
	public CasAuthenticationProvider casAuthenticationProvider(
			AbstractCasAssertionUserDetailsService casAssertionUserDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper,
			ServiceProperties serviceProperties, 
			TicketValidator ticketValidator) {

		CasAuthenticationProvider provider = new CasAuthenticationProvider();
		provider.setKey("casProvider");
		provider.setAuthoritiesMapper(authoritiesMapper);
		provider.setServiceProperties(serviceProperties);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(casAssertionUserDetailsService);

		return provider;
	}

	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint(SecurityCasProperties casProperties,
			ServerProperties serverProperties,
			ServiceProperties serviceProperties) {

		CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

		entryPoint.setEncodeServiceUrlWithSessionId(casProperties.isEncodeServiceUrlWithSessionId());
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties,
				serverProperties.getServlet().getContextPath(), casProperties.getServiceCallbackUrl()));
		entryPoint.setServiceProperties(serviceProperties);

		return entryPoint;
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class })
    @Order(109)
	static class CasWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    	
		private final SecurityCasProperties casProperties;
		private final SecurityCasAuthcProperties casAuthcProperties;
		private final ServiceProperties serviceProperties;
		
    	private final AuthenticationManager authenticationManager;
    	private final AuthenticationSuccessHandler authenticationSuccessHandler;
		private final AuthenticationFailureHandler authenticationFailureHandler;
		private final ServiceAuthenticationDetailsSource authenticationDetailsSource;
		private final CasAuthenticationEntryPoint authenticationEntryPoint;
 	    private final CasAuthenticationProvider authenticationProvider;
 	    private final ProxyGrantingTicketStorage proxyGrantingTicketStorage;
 	    
 	    private final LogoutSuccessHandler logoutSuccessHandler;
 	    private final List<LogoutHandler> logoutHandlers;
 	   
	    private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public CasWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityCasProperties casProperties,
				SecurityCasAuthcProperties casAuthcProperties,
				ServiceProperties serviceProperties,
				 
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<CasAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<CasAuthenticationProvider> authenticationProvider,
   				@Qualifier("casAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("casAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<LogoutHandler> logoutHandlers,
   				@Qualifier("casLogoutSuccessHandler") ObjectProvider<LogoutSuccessHandler> logoutSuccessHandler,
   				
   				ObjectProvider<ServiceAuthenticationDetailsSource> authenticationDetailsSourceProvider,
   				
   				ObjectProvider<ProxyGrantingTicketStorage> proxyGrantingTicketStorageProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
   				
   			) {
			
   			this.casProperties = casProperties;
   			this.casAuthcProperties = casAuthcProperties;
   			this.serviceProperties = serviceProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.authenticationDetailsSource = authenticationDetailsSourceProvider.getIfAvailable();
   			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.logoutHandlers = logoutHandlers.stream().collect(Collectors.toList());
   			this.logoutSuccessHandler = logoutSuccessHandler.getIfAvailable();
   			
   			this.proxyGrantingTicketStorage = proxyGrantingTicketStorageProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
		}

		public CasAuthenticationFilter authenticationProcessingFilter() {

			CasAuthenticationFilter authenticationFilter = new CasAuthenticationFilter();

			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authenticationDetailsSource).to(authenticationFilter::setAuthenticationDetailsSource);
			
			map.from(casAuthcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(serviceProperties).to(authenticationFilter::setServiceProperties);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(true).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			map.from(casProperties.isEagerlyCreateSessions()).to(authenticationFilter::setAllowSessionCreation);
			
			if (casProperties.isAcceptAnyProxy()) {
				map.from(authenticationFailureHandler).to(authenticationFilter::setProxyAuthenticationFailureHandler);
				map.from(proxyGrantingTicketStorage).to(authenticationFilter::setProxyGrantingTicketStorage);
				map.from(casProperties.getProxyReceptorUrl()).to(authenticationFilter::setProxyReceptorUrl); 
			}

			return authenticationFilter;
		}
		
		/**
		 * 	系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
		 */
		public LogoutFilter logoutFilter() {
			
			LogoutFilter logoutFilter = null;
			if(CollectionUtils.isEmpty(logoutHandlers)) {
				logoutFilter = new LogoutFilter(logoutSuccessHandler);
			} else {
				logoutFilter = new LogoutFilter(logoutSuccessHandler, logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
			}
			logoutFilter.setFilterProcessesUrl(casProperties.getLogout().getLogoutUrlPatterns());
			
			return logoutFilter;
		}
		
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	    }

	    @Override
		public void configure(HttpSecurity http) throws Exception {

	        http.csrf().disable(); // We don't need CSRF for Cas based authentication

	        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
	        
	        http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
	            .addFilterBefore(logoutFilter(), LogoutFilter.class);

	    }
	    
	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	//web.ignoring().antMatchers(casAuthcProperties.getPathPattern());
   	    }
		
	}
	
}
