package org.springframework.security.boot;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.AssertionThreadLocalFilter;
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
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
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.cas.*;
import org.springframework.security.boot.cas.ticket.DefaultProxyGrantingTicketStorageProvider;
import org.springframework.security.boot.cas.ticket.ProxyGrantingTicketStorageProvider;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.NullStatelessTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsExtSource;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.stream.Collectors;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityCasAuthcProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityCasFilterConfiguration {
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractCasAssertionUserDetailsService casAssertionUserDetailsService(SecurityCasAuthcProperties authcProperties) {
		return new GrantedAuthorityFromAssertionAttributesUserDetailsExtService(authcProperties);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider(SecurityCasAuthcProperties authcProperties) {
		return new DefaultProxyGrantingTicketStorageProvider(authcProperties);
	}

	@Bean
	@ConditionalOnMissingBean
	public ServiceAuthenticationDetailsSource authenticationDetailsSource(SecurityCasAuthcProperties authcProperties) {
		return new ServiceAuthenticationDetailsExtSource(authcProperties);
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
	public TicketValidator ticketValidator(SecurityCasAuthcProperties casProperties, ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider) {
		return new CasTicketValidator(casProperties, proxyGrantingTicketStorageProvider);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public CasAuthenticationProvider casAuthenticationProvider(
			AbstractCasAssertionUserDetailsService casAssertionUserDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper,
			SecurityCasAuthcProperties authcProperties,
			TicketValidator ticketValidator) {

		CasAuthenticationExtProvider provider = new CasAuthenticationExtProvider(authcProperties);
		provider.setKey("casProvider");
		provider.setAuthoritiesMapper(authoritiesMapper);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(casAssertionUserDetailsService);

		return provider;
	}

	@Bean
	@ConditionalOnMissingBean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint(SecurityCasAuthcProperties authcProperties) {

		CasAuthenticationExtEntryPoint entryPoint = new CasAuthenticationExtEntryPoint(authcProperties);
/*
		entryPoint.setEncodeServiceUrlWithSessionId(authcProperties.isEncodeServiceUrlWithSessionId());
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(authcProperties));
		entryPoint.setServiceProperties(serviceProperties);*/

		return entryPoint;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public CasAuthenticationSuccessHandler casAuthenticationSuccessHandler(SecurityCasAuthcProperties authcProperties,
			@Autowired(required = false) JwtPayloadRepository jwtPayloadRepository) {
		
		CasAuthenticationSuccessHandler successHandler = new CasAuthenticationSuccessHandler(authcProperties);
		
		successHandler.setAlwaysUseDefaultTargetUrl(authcProperties.isAlwaysUseDefaultTargetUrl());
		successHandler.setDefaultTargetUrl(authcProperties.getDefaultTargetUrl());
		successHandler.setTargetUrlParameter(authcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(authcProperties.isUseReferer());
		successHandler.setJwtPayloadRepository(jwtPayloadRepository);
		
		return successHandler;
		
	}

	@Configuration
	@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 60)
	static class CasWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {

		private final SecurityCasAuthcProperties authcProperties;
    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
		private final ServiceAuthenticationDetailsSource authenticationDetailsSource;
	    private final CasAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final CasAuthenticationFailureHandler authenticationFailureHandler;
	    private final CasProxyFailureHandler proxyFailureHandler;
	    private final ProxyGrantingTicketStorageProvider proxyGrantingTicketStorageProvider;
    	private final RememberMeServices rememberMeServices;
    	private final RedirectStrategy redirectStrategy;
    	private final SessionMappingStorage sessionMappingStorage;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		
		public CasWebSecurityConfigurerAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityCasAuthcProperties authcProperties,
   				SecuritySessionMgtProperties sessionMgtProperties,

				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<CasAuthenticationProvider> authenticationProvider,
				ObjectProvider<CasAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
				ObjectProvider<CasAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<ServiceAuthenticationDetailsSource> authenticationDetailsSourceProvider,
   				ObjectProvider<CasAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<CasProxyFailureHandler> proxyFailureHandlerProvider,
				ObjectProvider<ProxyGrantingTicketStorageProvider> proxyGrantingTicketStorageProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionMappingStorage> sessionMappingStorageProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
   				
   			) {
			
			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
			
   			this.authcProperties = authcProperties;

			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			this.authenticationDetailsSource = authenticationDetailsSourceProvider.getIfAvailable();
   			this.authenticationEntryPoint =  authenticationEntryPointProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandlerProvider.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandlerProvider.getIfAvailable( () -> authenticationFailureHandler());
   			this.proxyFailureHandler = proxyFailureHandlerProvider.getIfAvailable( () -> proxyFailureHandler());
   			this.proxyGrantingTicketStorageProvider = proxyGrantingTicketStorageProvider.getIfAvailable();
   			this.redirectStrategy = WebSecurityUtils.redirectStrategy(authcProperties);
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionMappingStorage = sessionMappingStorageProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
		}
		
		public CasAuthenticationFailureHandler authenticationFailureHandler() {
	    	
			CasAuthenticationFailureHandler failureHandler = new CasAuthenticationFailureHandler(authcProperties);

	    	failureHandler.setAllowSessionCreation(getSessionMgtProperties().isAllowSessionCreation());
			failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
			failureHandler.setRedirectStrategy(redirectStrategy);
			failureHandler.setUseForward(authcProperties.isUseForward());
			return failureHandler;
			
		}
	    
	   	public CasProxyFailureHandler proxyFailureHandler() {
	    	
	    	CasProxyFailureHandler failureHandler = new CasProxyFailureHandler(authcProperties);
			
			failureHandler.setAllowSessionCreation(getSessionMgtProperties().isAllowSessionCreation());
			failureHandler.setDefaultFailureUrl(authcProperties.getFailureUrl());
			failureHandler.setRedirectStrategy(redirectStrategy);
			failureHandler.setUseForward(authcProperties.isUseForward());
			return failureHandler;
			
	   	}

		public CasAuthenticationFilter authenticationProcessingFilter() throws Exception {

			CasAuthenticationExtFilter authenticationFilter = new CasAuthenticationExtFilter(authcProperties);

			/*
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			authenticationSuccessHandler.setRedirectStrategy(redirectStrategy);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			map.from(authenticationDetailsSource).to(authenticationFilter::setAuthenticationDetailsSource);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			map.from(authcProperties.isEagerlyCreateSessions()).to(authenticationFilter::setAllowSessionCreation);

			if(authcProperties.isAcceptAnyProxy()){
				map.from(proxyGrantingTicketStorageProvider).to(authenticationFilter::setProxyGrantingTicketStorageProvider);
				map.from(proxyFailureHandler).to(authenticationFilter::setProxyAuthenticationFailureHandler);
				map.from(authcProperties.getProxyReceptorUrl()).to(authenticationFilter::setProxyReceptorUrl2);
			}

			return authenticationFilter;
		}
		
		/*
		 * 	单点注销Session监听器
		 */
	    @Bean
	    public ServletListenerRegistrationBean<CasSingleSignOutHttpSessionListener> singleSignOutHttpSessionListener(){
	        ServletListenerRegistrationBean<CasSingleSignOutHttpSessionListener> servletListenerRegistrationBean =
	                new ServletListenerRegistrationBean<>();
			CasSingleSignOutHttpSessionListener listener = new CasSingleSignOutHttpSessionListener(sessionMappingStorage);
	        servletListenerRegistrationBean.setListener(listener);
	        servletListenerRegistrationBean.setEnabled(true);
	        servletListenerRegistrationBean.setOrder(1);
	        return servletListenerRegistrationBean;
	    }

	    /*
		 * 	CAS SignOut Filter
		 * 	该过滤器用于实现单点登出功能，单点退出配置，一定要放在其他filter之前
		 */
		public CasSingleSignOutFilter singleSignOutFilter() {
			CasSingleSignOutFilter singleSignOutFilter = new CasSingleSignOutFilter(authcProperties, sessionMappingStorage);
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
	    	
	    	http.antMatcher(authcProperties.getPathPattern())
				.exceptionHandling()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.httpBasic()
	        	.disable()
	        	.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
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

