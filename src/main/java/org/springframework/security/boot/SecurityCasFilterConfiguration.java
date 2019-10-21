package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.cas.CasTicketValidatorConfiguration;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.NullStatelessTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.cas.userdetails.GrantedAuthorityFromAssertionAttributesUserDetailsService;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class, ServerProperties.class })
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
			SessionMappingStorage sessionMappingStorage) {
		
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
		
		filterRegistration.addUrlPatterns(casProperties.getSsoPathPatterns());
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
	public FilterRegistrationBean<AssertionThreadLocalFilter> assertionThreadLocalFilter(SecurityCasProperties casProperties) {
		FilterRegistrationBean<AssertionThreadLocalFilter> filterRegistration = new FilterRegistrationBean<AssertionThreadLocalFilter>();
		filterRegistration.setFilter(new AssertionThreadLocalFilter());
		filterRegistration.setEnabled(casProperties.isEnabled());
		filterRegistration.addUrlPatterns(casProperties.getAssertionPathPatterns());
		filterRegistration.setOrder(6);
		return filterRegistration;
	}
	

	@Bean
	public ServiceProperties serviceProperties(SecurityCasProperties casProperties) {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setArtifactParameter(casProperties.getArtifactParameterName());
		serviceProperties.setAuthenticateAllArtifacts(casProperties.isAuthenticateAllArtifacts());
		serviceProperties.setSendRenew(casProperties.isRenew());
		serviceProperties.setService(casProperties.getService());
		serviceProperties.setServiceParameter(casProperties.getServiceParameterName());
		return serviceProperties;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractCasAssertionUserDetailsService casAssertionUserDetailsService(SecurityCasProperties casProperties) {
		String[] attributes = ArrayUtils.isEmpty(casProperties.getAttributes()) ? new String[] {} : casProperties.getAttributes();
		return new GrantedAuthorityFromAssertionAttributesUserDetailsService(attributes);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ProxyGrantingTicketStorage proxyGrantingTicketStorage(SecurityCasProperties casProperties) {
		return new ProxyGrantingTicketStorageImpl(casProperties.getTimeout());
	}

	@Bean
	@ConditionalOnMissingBean
	public ServiceAuthenticationDetailsSource authenticationDetailsSource(ServiceProperties serviceProperties) {
		return new ServiceAuthenticationDetailsSource(serviceProperties);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public SessionMappingStorage sessionMappingStorage() {
		return new HashMapBackedSessionMappingStorage();
	}
	  
	@Bean
	@ConditionalOnMissingBean
	public StatelessTicketCache statelessTicketCache() {
		return new NullStatelessTicketCache();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public TicketValidator ticketValidator(SecurityCasProperties casProperties, ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
		CasTicketValidatorConfiguration ticketValidatorConfig = new CasTicketValidatorConfiguration(proxyGrantingTicketStorage);
		return ticketValidatorConfig.retrieveTicketValidator(casProperties);
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
	
	@Bean("casLogoutSuccessHandler")
	public LogoutSuccessHandler castLogoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class })
    @Order(109)
	static class CasWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {

		private final SecurityBizProperties bizProperties;
		private final SecurityCasProperties casProperties;
		private final ServiceProperties serviceProperties;
		
		private final AuthenticationManager authenticationManager;
		private final ServiceAuthenticationDetailsSource authenticationDetailsSource;
		private final CasAuthenticationEntryPoint authenticationEntryPoint;
	    private final CasAuthenticationProvider authenticationProvider;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final CsrfTokenRepository csrfTokenRepository;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutSuccessHandler logoutSuccessHandler;
	    private final List<LogoutHandler> logoutHandlers;
	    private final ProxyGrantingTicketStorage proxyGrantingTicketStorage;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
		
		public CasWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityCasProperties casProperties,
				ServiceProperties serviceProperties,
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<CasAuthenticationProvider> authenticationProvider,
   				ObjectProvider<ServiceAuthenticationDetailsSource> authenticationDetailsSourceProvider,
   				ObjectProvider<CasAuthenticationEntryPoint> authenticationEntryPointProvider,
   				@Qualifier("casAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				@Qualifier("casAuthenticationFailureHandler") ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
   				@Qualifier("casLogoutSuccessHandler") ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<ProxyGrantingTicketStorage> proxyGrantingTicketStorageProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider
   				
   			) {
			
			super(bizProperties);
			
			this.bizProperties = bizProperties;
   			this.casProperties = casProperties;
   			this.serviceProperties = serviceProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationDetailsSource = authenticationDetailsSourceProvider.getIfAvailable();
   			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.csrfTokenRepository = csrfTokenRepositoryProvider.getIfAvailable();
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
   			this.logoutHandlers = logoutHandlerProvider.stream().collect(Collectors.toList());
   			this.proxyGrantingTicketStorage = proxyGrantingTicketStorageProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();
		}

		@Override
		protected AuthenticationManager authenticationManager() throws Exception {
			return authenticationManager == null ? super.authenticationManager() : authenticationManager;
		}
		
		public CasAuthenticationFilter authenticationProcessingFilter() throws Exception {

			CasAuthenticationFilter authenticationFilter = new CasAuthenticationFilter();

			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authenticationManager()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authenticationDetailsSource).to(authenticationFilter::setAuthenticationDetailsSource);
			
			map.from(casProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
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
		
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	        super.configure(auth);
	    }

	    @Override
		public void configure(HttpSecurity http) throws Exception {
	    	
	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = casProperties.getLogout();
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.headers().cacheControl(); // 禁用缓存
	    	http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(logout.getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.expiredUrl(logout.getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.logoutUrl(logout.getPathPatterns())
   	    		.logoutSuccessHandler(logoutSuccessHandler)
   	    		.addLogoutHandler(new CompositeLogoutHandler(logoutHandlers))
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   	        	.antMatcher(casProperties.getPathPattern())
	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
   	    	
   	    	// CSRF 配置
   	    	SecurityCsrfProperties csrf = casProperties.getCsrf();
   	    	if(csrf.isEnabled()) {
   	       		http.csrf()
   				   	.csrfTokenRepository(csrfTokenRepository)
   				   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
   					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
   	        } else {
   	        	http.csrf().disable();
   	        }
	    	super.configure(http);
	    }
	    
		
	}
	
}
