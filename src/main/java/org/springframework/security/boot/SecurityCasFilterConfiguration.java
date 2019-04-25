package org.springframework.security.boot;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.springframework.beans.BeanInstantiationException;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.SecurityCasProperties.CaMode;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.cors.CorsUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureAfter(SecurityBizFilterAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityCasFilterConfiguration extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private SecurityCasProperties casProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	
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
    
	@Bean
	public CasAuthenticationFilter casAuthenticationFilter(
			AuthenticationManager authenticationManager, 
			AuthenticationSuccessHandler successHandler, 
    		AuthenticationFailureHandler failureHandler,
			RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy,
			MessageSource messageSource,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			ServiceProperties serviceProperties,
			ObjectMapper objectMapper,
			@Autowired(required = false) ProxyGrantingTicketStorage proxyGrantingTicketStorage) {

		CasAuthenticationFilter authcFilter = new CasAuthenticationFilter();

		authcFilter.setAllowSessionCreation(casProperties.getSessionMgt().isAllowSessionCreation());
		authcFilter.setApplicationEventPublisher(eventPublisher);
		authcFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authcFilter.setAuthenticationFailureHandler(failureHandler);
		authcFilter.setAuthenticationManager(authenticationManager);
		authcFilter.setAuthenticationSuccessHandler(successHandler);
		authcFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(casProperties.getAuthc().getLoginUrlPatterns())) {
			authcFilter.setFilterProcessesUrl(casProperties.getAuthc().getLoginUrlPatterns());
		}
		authcFilter.setMessageSource(messageSource);
		// 认证代理设置
		if (StringUtils.hasText(casProperties.getProxyReceptorUrl())) {
			authcFilter.setProxyAuthenticationFailureHandler(failureHandler);
			if(proxyGrantingTicketStorage == null && StringUtils.hasText(casProperties.getProxyGrantingTicketStorageClass())) {
				try {
					proxyGrantingTicketStorage = (ProxyGrantingTicketStorage) BeanUtils.instantiateClass(Class.forName(casProperties.getProxyGrantingTicketStorageClass()));
				} catch (BeanInstantiationException e) {
				} catch (ClassNotFoundException e) {
				}
			}
			if(proxyGrantingTicketStorage != null) {
				authcFilter.setProxyGrantingTicketStorage(proxyGrantingTicketStorage);
			}
			authcFilter.setProxyReceptorUrl(casProperties.getProxyReceptorUrl());	
		}
		
		authcFilter.setRememberMeServices(rememberMeServices);
		authcFilter.setServiceProperties(serviceProperties);
		authcFilter.setSessionAuthenticationStrategy(sessionStrategy);

		return authcFilter;
	}
	
	/**
	 * 	系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	public LogoutFilter logoutFilter(List<LogoutHandler> logoutHandlers) {
		
		String logoutRedirectPath = casProperties.getAuthc().getLoginUrl();
		// 登录注销后的重定向地址：直接进入登录页面
		if (CaMode.sso.compareTo(casProperties.getCaMode()) == 0) {
			logoutRedirectPath = CasUrlUtils.constructLogoutRedirectUrl(casProperties,
					serverProperties.getServlet().getContextPath(), casProperties.getAuthc().getLoginUrl());
		}
		LogoutFilter logoutFilter = new LogoutFilter(logoutRedirectPath, logoutHandlers.toArray(new LogoutHandler[logoutHandlers.size()]));
		logoutFilter.setFilterProcessesUrl(casProperties.getLogout().getLogoutUrlPatterns());
		return logoutFilter;
	}
	
	@Bean
	public SingleSignOutFilter singleSignOutFilter() {
		// 单点注销的过滤器，必须配置在SpringSecurity的过滤器链中，如果直接配置在Web容器中，貌似是不起作用的。我自己的是不起作用的。
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(casProperties.getCasServerUrlPrefix());
        return singleSignOutFilter;
	}
	
	@Autowired
    private CasAuthenticationEntryPoint casAuthenticationEntryPoint;
    @Autowired
    private CasAuthenticationProvider casAuthenticationProvider;
    @Autowired
    private CasAuthenticationFilter casAuthenticationFilter;
    @Autowired
    private LogoutFilter logoutFilter;
    @Autowired 
    private SingleSignOutFilter singleSignOutFilter;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();

        http.csrf().disable(); // We don't need CSRF for JWT based authentication

        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/static/**").permitAll() // 不拦截静态资源
                .antMatchers("/api/**").permitAll()  // 不拦截对外API
                    .anyRequest().authenticated();  // 所有资源都需要登陆后才可以访问。

        http.logout()
        	.invalidateHttpSession(true)
        	//.addLogoutHandler(logoutHandler)
        	//.logoutSuccessHandler(logoutSuccessHandler)
        	//.logoutSuccessUrl(logoutSuccessUrl)
        	//.logoutUrl(logoutUrl)
        	.permitAll();  // 不拦截注销

        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint);
       
        
        http.addFilter(casAuthenticationFilter)
                .addFilterBefore(logoutFilter, LogoutFilter.class)
                .addFilterBefore(singleSignOutFilter, CasAuthenticationFilter.class);

        http.antMatcher("/**");
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(casAuthenticationProvider);
    }
    
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}
	
}
