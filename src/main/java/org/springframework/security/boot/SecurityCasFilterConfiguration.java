package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

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
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.cas.userdetails.CasAuthenticationUserDetailsService;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
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
    
    @Bean("casLogoutSuccessHandler")
	public LogoutSuccessHandler logoutSuccessHandler(SecurityCasProperties casProperties) {
		return new ForwardLogoutSuccessHandler(casProperties.getLoginUrl());
	}
    
	@Bean
	public CasAuthenticationProvider casAuthenticationProvider(
			CasAuthenticationUserDetailsService userDetailsService,
			GrantedAuthoritiesMapper authoritiesMapper,
			ServiceProperties serviceProperties, 
			TicketValidator ticketValidator) {

		CasAuthenticationProvider provider = new CasAuthenticationProvider();
		provider.setKey("casProvider");
		provider.setAuthoritiesMapper(authoritiesMapper);
		provider.setServiceProperties(serviceProperties);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(userDetailsService);

		return provider;
	}

	@Bean
	public CasAuthenticationEntryPoint casAuthenticationEntryPoint(SecurityCasProperties casProperties,
			ServerProperties serverProperties,
			ServiceProperties serviceProperties) {

		CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

		entryPoint.setEncodeServiceUrlWithSessionId(casProperties.isEncodeServiceUrlWithSessionId());
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties,
				serverProperties.getServlet().getContextPath(), casProperties.getServerCallbackUrl()));
		entryPoint.setServiceProperties(serviceProperties);

		return entryPoint;
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class })
    @Order(106)
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
 	    private final SessionMappingStorage sessionMappingStorage;
 	    
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
   				ObjectProvider<SessionMappingStorage> sessionMappingStorageProvider,
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
   			this.sessionMappingStorage = sessionMappingStorageProvider.getIfAvailable();
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
			
			if (StringUtils.hasText(casProperties.getProxyReceptorUrl())) {
				authenticationFilter.setProxyAuthenticationFailureHandler(authenticationFailureHandler);
				if(proxyGrantingTicketStorage != null) {
					authenticationFilter.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
				}
				authenticationFilter.setProxyReceptorUrl(casProperties.getProxyReceptorUrl());	
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
		
		public SingleSignOutFilter singleSignOutFilter() {
			
	        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
	        
	        singleSignOutFilter.setArtifactParameterName(casProperties.getArtifactParameterName());
	        singleSignOutFilter.setCasServerUrlPrefix(casProperties.getPrefixUrl());
	        singleSignOutFilter.setIgnoreInitConfiguration(casProperties.isIgnoreInitConfiguration());
	        singleSignOutFilter.setLogoutCallbackPath(casProperties.getLogout().getLogoutSuccessUrl());
	        singleSignOutFilter.setLogoutParameterName(casProperties.getLogoutParameterName());
	        singleSignOutFilter.setRelayStateParameterName(casProperties.getRelayStateParameterName());
	        singleSignOutFilter.setSessionMappingStorage(sessionMappingStorage);
	        
	        return singleSignOutFilter;
		}
		
		public AssertionThreadLocalFilter assertionThreadLocalFilter() {
	        return new AssertionThreadLocalFilter();
		}
		
		@Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.authenticationProvider(authenticationProvider);
	    }

	    @Override
	    protected void configure(HttpSecurity http) throws Exception {

	        http.csrf().disable(); // We don't need CSRF for Cas based authentication

	        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);
	        
	        http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
	                .addFilterBefore(logoutFilter(), LogoutFilter.class)
	                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
	                .addFilter(assertionThreadLocalFilter());

	    }
	    
	    @Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring().antMatchers(casAuthcProperties.getPathPattern());
   	    }
		
	}
	
}
