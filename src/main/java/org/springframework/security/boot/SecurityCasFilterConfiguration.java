package org.springframework.security.boot;

import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.cas.CasAuthenticationExtProvider;
import org.springframework.security.boot.cas.CasAuthenticationFailureHandler;
import org.springframework.security.boot.cas.CasAuthenticationSuccessHandler;
import org.springframework.security.boot.cas.CasProxyFailureHandler;
import org.springframework.security.boot.cas.CasTicketValidatorConfiguration;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.NullStatelessTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.cas.userdetails.GrantedAuthorityFromAssertionAttributesUserDetailsService;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.ForwardLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityCasAuthcProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityCasFilterConfiguration {
	
	@Bean
	public ServiceProperties serviceProperties(SecurityCasProperties casProperties,
			SecurityCasAuthcProperties authcProperties) {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setArtifactParameter(authcProperties.getArtifactParameterName());
		serviceProperties.setAuthenticateAllArtifacts(authcProperties.isAuthenticateAllArtifacts());
		serviceProperties.setSendRenew(authcProperties.isRenew());
		serviceProperties.setService(authcProperties.getServiceUrl());
		serviceProperties.setServiceParameter(authcProperties.getServiceParameterName());
		return serviceProperties;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractCasAssertionUserDetailsService casAssertionUserDetailsService(SecurityCasAuthcProperties authcProperties) {
		String[] attributes = ArrayUtils.isEmpty(authcProperties.getAttributes()) ? new String[] {} : authcProperties.getAttributes();
		return new GrantedAuthorityFromAssertionAttributesUserDetailsService(attributes);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ProxyGrantingTicketStorage proxyGrantingTicketStorage(
			SecurityCasAuthcProperties authcProperties) {
		return new ProxyGrantingTicketStorageImpl(authcProperties.getTimeout());
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
	public TicketValidator ticketValidator(SecurityCasAuthcProperties casProperties, ProxyGrantingTicketStorage proxyGrantingTicketStorage) {
		CasTicketValidatorConfiguration ticketValidatorConfig = new CasTicketValidatorConfiguration(proxyGrantingTicketStorage);
		return ticketValidatorConfig.retrieveTicketValidator(casProperties);
	}
	
	@Bean
	public CasAuthenticationProvider casAuthenticationProvider(
			AbstractCasAssertionUserDetailsService casAssertionUserDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper,
			ServiceProperties serviceProperties, 
			TicketValidator ticketValidator) {

		CasAuthenticationExtProvider provider = new CasAuthenticationExtProvider();
		provider.setKey("casProvider");
		provider.setAuthoritiesMapper(authoritiesMapper);
		provider.setServiceProperties(serviceProperties);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(casAssertionUserDetailsService);

		return provider;
	}

	/**
	 * 
	 * TODO
	 * @author 		： <a href="https://github.com/vindell">wandl</a>
	 * @return
	 * @throws Exception
	 * @see org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint
	 */
	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint(
			SecurityCasAuthcProperties authcProperties,
			ServerProperties serverProperties,
			ServiceProperties serviceProperties) {

		CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

		entryPoint.setEncodeServiceUrlWithSessionId(authcProperties.isEncodeServiceUrlWithSessionId());
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(authcProperties));
		entryPoint.setServiceProperties(serviceProperties);

		return entryPoint;
	}
	
	@Bean("casAuthenticationSuccessHandler")
	public CasAuthenticationSuccessHandler casAuthenticationSuccessHandler(SecurityCasAuthcProperties authcProperties,
			@Autowired(required = false) JwtPayloadRepository jwtPayloadRepository) {
		
		CasAuthenticationSuccessHandler successHandler = new CasAuthenticationSuccessHandler(authcProperties);
		
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getSuccessUrl());
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());
		successHandler.setJwtPayloadRepository(jwtPayloadRepository);
		
		return successHandler;
		
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 60)
	static class CasWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {

		private final SecurityCasAuthcProperties authcProperties;
		private final ServiceProperties serviceProperties;
		
		private final ServiceAuthenticationDetailsSource authenticationDetailsSource;
		private final CasAuthenticationEntryPoint authenticationEntryPoint;
	    private final CasAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final AuthenticationFailureHandler proxyFailureHandler;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutSuccessHandler logoutSuccessHandler;
	    private final LogoutHandler logoutHandler;
	    private final ProxyGrantingTicketStorage proxyGrantingTicketStorage;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final RedirectStrategy redirectStrategy;
    	private final SessionRegistry sessionRegistry;
    	private final SessionMappingStorage sessionMappingStorage;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
		
		public CasWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityCasAuthcProperties authcProperties,
				ServiceProperties serviceProperties,
				
				ObjectProvider<CasAuthenticationProvider> authenticationProvider,
				ObjectProvider<CasAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
				ObjectProvider<ServiceAuthenticationDetailsSource> authenticationDetailsSourceProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<CasAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<ProxyGrantingTicketStorage> proxyGrantingTicketStorageProvider,
   				ObjectProvider<SessionMappingStorage> sessionMappingStorageProvider
   				
   			) {
			
			
			
			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
			
   			this.authcProperties = authcProperties;
   			this.serviceProperties = serviceProperties;
   			
   			this.authenticationDetailsSource = authenticationDetailsSourceProvider.getIfAvailable();
   			this.authenticationEntryPoint =  authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandlerProvider.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler();
   			this.proxyFailureHandler = proxyFailureHandler();
   			this.invalidSessionStrategy = super.invalidSessionStrategy();
   			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
   			this.logoutSuccessHandler = logoutSuccessHandler();
   			this.proxyGrantingTicketStorage = proxyGrantingTicketStorageProvider.getIfAvailable();
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.redirectStrategy = super.redirectStrategy();
   			this.sessionRegistry = super.sessionRegistry();
   			this.sessionMappingStorage = sessionMappingStorageProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
   			this.sessionInformationExpiredStrategy = super.sessionInformationExpiredStrategy();
		}
		

		

		public AuthenticationFailureHandler authenticationFailureHandler() {
	    	
			CasAuthenticationFailureHandler failureHandler = new CasAuthenticationFailureHandler(authcProperties);

	    	failureHandler.setAllowSessionCreation(authcProperties.getSessionMgt().isAllowSessionCreation());
			failureHandler.setDefaultFailureUrl(authcProperties.getSessionMgt().getFailureUrl());
			failureHandler.setRedirectStrategy(redirectStrategy);
			failureHandler.setUseForward(authcProperties.getSessionMgt().isUseForward());
			return failureHandler;
			
		}
	    
	   	public AuthenticationFailureHandler proxyFailureHandler() {
	    	
	    	CasProxyFailureHandler failureHandler = new CasProxyFailureHandler(authcProperties);
			
			failureHandler.setAllowSessionCreation(authcProperties.getSessionMgt().isAllowSessionCreation());
			failureHandler.setDefaultFailureUrl(authcProperties.getSessionMgt().getFailureUrl());
			failureHandler.setRedirectStrategy(redirectStrategy);
			failureHandler.setUseForward(authcProperties.getSessionMgt().isUseForward());
			return failureHandler;
			
	   	}

		public LogoutSuccessHandler logoutSuccessHandler() {
			return new ForwardLogoutSuccessHandler(authcProperties.getLoginUrl());
		}

		public CasAuthenticationFilter authenticationProcessingFilter() throws Exception {

			CasAuthenticationFilter authenticationFilter = new CasAuthenticationFilter();

			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			authenticationSuccessHandler.setRedirectStrategy(redirectStrategy);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authenticationDetailsSource).to(authenticationFilter::setAuthenticationDetailsSource);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(serviceProperties).to(authenticationFilter::setServiceProperties);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			map.from(authcProperties.isEagerlyCreateSessions()).to(authenticationFilter::setAllowSessionCreation);
			
			if (authcProperties.isAcceptAnyProxy()) {
				map.from(proxyFailureHandler).to(authenticationFilter::setProxyAuthenticationFailureHandler);
				map.from(proxyGrantingTicketStorage).to(authenticationFilter::setProxyGrantingTicketStorage);
				map.from(authcProperties.getProxyReceptorUrl()).to(authenticationFilter::setProxyReceptorUrl); 
			}
			return authenticationFilter;
		}
		
		/**
		 * 	单点注销Session监听器
		 */
	    @Bean
	    public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListener(){
	        ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> servletListenerRegistrationBean =
	                new ServletListenerRegistrationBean<SingleSignOutHttpSessionListener>();
	        servletListenerRegistrationBean.setListener(new SingleSignOutHttpSessionListener());
	        servletListenerRegistrationBean.setEnabled(true);
	        servletListenerRegistrationBean.setOrder(1);
	        return servletListenerRegistrationBean;
	    }

	    /*
		 * 	CAS SignOut Filter
		 * 	该过滤器用于实现单点登出功能，单点退出配置，一定要放在其他filter之前
		 */
		public SingleSignOutFilter singleSignOutFilter() {
			
			SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getArtifactParameterName()).to(singleSignOutFilter::setArtifactParameterName);
			map.from(authcProperties.getPrefixUrl()).to(singleSignOutFilter::setCasServerUrlPrefix);
			map.from(true).to(singleSignOutFilter::setIgnoreInitConfiguration);
			map.from("").to(singleSignOutFilter::setLogoutCallbackPath);
			map.from(authcProperties.getLogoutParameterName()).to(singleSignOutFilter::setLogoutParameterName);
			map.from(authcProperties.getRelayStateParameterName()).to(singleSignOutFilter::setRelayStateParameterName);
			map.from(sessionMappingStorage).to(singleSignOutFilter::setSessionMappingStorage);
			
			return singleSignOutFilter;
		}
		
		/*
		 * 	CAS Assertion Thread Local Filter
		 * 	该过滤器使得可以通过org.jasig.cas.client.util.AssertionHolder来获取用户的登录名。
		 * 	比如AssertionHolder.getAssertion().getPrincipal().getName()。
		 * 	这个类把Assertion信息放在ThreadLocal变量中，这样应用程序不在web层也能够获取到当前登录信息
		 */
		public AssertionThreadLocalFilter assertionThreadLocalFilter() {
			return new AssertionThreadLocalFilter();
		}
		
		/*
		 * 	CAS HttpServletRequest Wrapper Filter
		 * 	该过滤器对HttpServletRequest请求包装， 可通过HttpServletRequest的getRemoteUser()方法获得登录用户的登录名
		 */
		public HttpServletRequestWrapperFilter requestWrapperFilter() {
			HttpServletRequestWrapperFilter wrapperFilter = new HttpServletRequestWrapperFilter();
			wrapperFilter.setIgnoreInitConfiguration(true);
			return wrapperFilter;
		}

	    @Override
		public void configure(HttpSecurity http) throws Exception {
	    	
	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = authcProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = authcProperties.getLogout();
	    	
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
   	    		.addLogoutHandler(logoutHandler)
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	// 异常处理
   	        	.and()
   	        	.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.requestMatcher(new OrRequestMatcher(new AntPathRequestMatcher(authcProperties.getPathPattern())))
   	        	.antMatcher(authcProperties.getPathPattern())
	        	.addFilterAt(authenticationProcessingFilter(), CasAuthenticationFilter.class)
   	            .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
   	            .addFilterAfter(assertionThreadLocalFilter(), CasAuthenticationFilter.class)
   	            .addFilterAfter(requestWrapperFilter(), AssertionThreadLocalFilter.class);
   	    	
   	    	super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    }
	    
	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }
	    
	}
	
}

