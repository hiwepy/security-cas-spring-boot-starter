package org.springframework.security.boot;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.SecurityCasProperties.CaMode;
import org.springframework.security.boot.utils.CasUrlUtils;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetailsSource;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityCasProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityCasProperties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityCasWebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityCasProperties casProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;

	/**
	 * 登录监听：实现该接口可监听账号登录失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("loginListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "loginListeners") public List<LoginListener>
	 *                                loginListeners() {
	 * 
	 *                                List<LoginListener> loginListeners = new
	 *                                ArrayList<LoginListener>();
	 * 
	 *                                Map<String, LoginListener> beansOfType =
	 *                                getApplicationContext().getBeansOfType(LoginListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String, LoginListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                loginListeners.add(ite.next().getValue()); } }
	 * 
	 *                                return loginListeners; }
	 */

	/**
	 * Realm 执行监听：实现该接口可监听认证失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("realmListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "realmListeners") public
	 *                                List<PrincipalRealmListener> realmListeners()
	 *                                {
	 * 
	 *                                List<PrincipalRealmListener> realmListeners =
	 *                                new ArrayList<PrincipalRealmListener>();
	 * 
	 *                                Map<String, PrincipalRealmListener>
	 *                                beansOfType =
	 *                                getApplicationContext().getBeansOfType(PrincipalRealmListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String,
	 *                                PrincipalRealmListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                realmListeners.add(ite.next().getValue()); } }
	 * 
	 *                                return realmListeners; }
	 */

	/**
	 * 注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 * 
	 * @Bean("logoutListeners")
	 * 
	 * @ConditionalOnMissingBean(name = "logoutListeners") public
	 *                                List<LogoutListener> logoutListeners() {
	 * 
	 *                                List<LogoutListener> logoutListeners = new
	 *                                ArrayList<LogoutListener>();
	 * 
	 *                                Map<String, LogoutListener> beansOfType =
	 *                                getApplicationContext().getBeansOfType(LogoutListener.class);
	 *                                if (!ObjectUtils.isEmpty(beansOfType)) {
	 *                                Iterator<Entry<String, LogoutListener>> ite =
	 *                                beansOfType.entrySet().iterator(); while
	 *                                (ite.hasNext()) {
	 *                                logoutListeners.add(ite.next().getValue()); }
	 *                                }
	 * 
	 *                                return logoutListeners; }
	 */

	/**
	 * 系统登录注销过滤器；默认：org.apache.shiro.spring.boot.cas.filter.CasLogoutFilter
	 * 
	 * @Bean("logout")
	 * 
	 * @ConditionalOnMissingBean(name = "logout") public
	 *                                FilterRegistrationBean<BizLogoutFilter>
	 *                                logoutFilter(List<LogoutListener>
	 *                                logoutListeners){
	 * 
	 *                                FilterRegistrationBean<BizLogoutFilter>
	 *                                registration = new
	 *                                FilterRegistrationBean<BizLogoutFilter>();
	 *                                BizLogoutFilter logoutFilter = new
	 *                                BizLogoutFilter();
	 * 
	 *                                //登录注销后的重定向地址：直接进入登录页面
	 *                                logoutFilter.setRedirectUrl(bizProperties.getRedirectUrl());
	 *                                registration.setFilter(logoutFilter);
	 *                                //注销监听：实现该接口可监听账号注销失败和成功的状态，从而做业务系统自己的事情，比如记录日志
	 *                                logoutFilter.setLogoutListeners(logoutListeners);
	 * 
	 *                                registration.setEnabled(false); return
	 *                                registration; }
	 */

	/**
	 * 默认的Session过期过滤器 ：解决Ajax请求期间会话过期异常处理
	 * 
	 * @Bean("sessionExpired")
	 * 
	 * @ConditionalOnMissingBean(name = "sessionExpired") public
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>
	 *                                sessionExpiredFilter(){
	 * 
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>
	 *                                registration = new
	 *                                FilterRegistrationBean<HttpServletSessionExpiredFilter>();
	 *                                registration.setFilter(new
	 *                                HttpServletSessionExpiredFilter());
	 * 
	 *                                registration.setEnabled(false); return
	 *                                registration; }
	 */

	@Bean
	@ConditionalOnMissingBean
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
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource(
			ServiceProperties serviceProperties) {
		return new ServiceAuthenticationDetailsSource(serviceProperties);
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler successHandler() {
		SimpleUrlAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
		return successHandler;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler failureHandler() {
		return new SimpleUrlAuthenticationFailureHandler(bizProperties.getFailureUrl());
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	@Bean
	@ConditionalOnMissingBean
	public AbstractAuthenticationProcessingFilter authenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy, ServiceProperties serviceProperties) {

		CasAuthenticationFilter authenticationFilter = new CasAuthenticationFilter();

		authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authenticationFilter.setServiceProperties(serviceProperties);

		return authenticationFilter;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint(ServiceProperties serviceProperties) {
		
		CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();

		entryPoint.setEncodeServiceUrlWithSessionId(false);
		entryPoint.setLoginUrl(CasUrlUtils.constructLoginRedirectUrl(casProperties, serverProperties.getServlet().getContextPath(), casProperties.getServerCallbackUrl()));
		entryPoint.setServiceProperties(serviceProperties);
		
		return entryPoint;
	}

	@Bean
	public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
		return new Cas20ServiceTicketValidator(casProperties.getCasServerUrlPrefix());
	}

	@Bean
	public CasAuthenticationProvider casAuthenticationProvider(
			AuthenticationUserDetailsService<CasAssertionAuthenticationToken> userDetailsService,
			ServiceProperties serviceProperties, 
			Cas20ServiceTicketValidator ticketValidator) {
		
		CasAuthenticationProvider provider = new CasAuthenticationProvider();
		provider.setKey("casProvider");
		provider.setServiceProperties(serviceProperties);
		provider.setTicketValidator(ticketValidator);
		provider.setAuthenticationUserDetailsService(userDetailsService);

		return provider;
	}

	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		
		String logoutRedirectPath = bizProperties.getLoginUrl();
		// 登录注销后的重定向地址：直接进入登录页面
		if (CaMode.sso.compareTo(casProperties.getCaMode()) == 0) {
			logoutRedirectPath = CasUrlUtils.constructLogoutRedirectUrl(casProperties,
					serverProperties.getServlet().getContextPath(), bizProperties.getLoginUrl());
		}
		LogoutFilter logoutFilter = new LogoutFilter(logoutRedirectPath, new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
