package com.maple.security.browser;

import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.social.security.SpringSocialConfigurer;

import com.maple.security.core.authentication.FormAuthenticationConfig;
import com.maple.security.core.authentication.mobile.SmsAuthenticationSecurityConfig;
import com.maple.security.core.authorize.AuthorizeConfigManager;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * browser 配置类
 * 
 * @author hzc
 *
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter{
	
	/**
	 * 系统配置
	 */
	@Autowired
	private SecurityProperties securityProperties;
	
	/**
	 * 验证码配置信息
	 */
	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;
	
	/**
	 * remember 的token的存取器
	 */
	@Autowired
	private PersistentTokenRepository persistentTokenRepository;
	
	/**
	 * 获取用户信息的类
	 */
	@Autowired
	private UserDetailsService userDetailsService;
	
	/**
	 * 手机短信验证码配置类
	 */
	@Autowired
	private SmsAuthenticationSecurityConfig smsAuthenticationSecurityConfig;
	
	/**
	 * 第三方登录配置类
	 */
	@Autowired
	private SpringSocialConfigurer mapleSocialSecurityConfig;
	
	/**
	 * 表单登录配置
	 */
	@Autowired
	private FormAuthenticationConfig formAuthenticationConfig;
	
	/**
	 * session 超出登录数的处理类
	 */
	@Autowired
	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
	
	/**
	 * session 失效的处理类
	 */
	@Autowired
	private InvalidSessionStrategy invalidSessionStrategy;
	
	/**
	 * 退出成功处理器
	 */
	@Autowired
	private LogoutSuccessHandler logoutSuccessHandler;
	
	@Autowired
	private AuthorizeConfigManager authorizeConfigManager;
	
	@Autowired(required = false)
	private Set<BrowserSecurityConfigCallback> configCallbacks;
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers(HttpMethod.GET, "/**/*.css", "/**/*.js", "/**/*.png", "/**/*.gif", "/**/*.jpg");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		if(CollectionUtils.isNotEmpty(configCallbacks)) {
			configCallbacks.forEach(callback -> callback.config(http));
		}
		
		formAuthenticationConfig.configure(http);
		
		http.apply(validateCodeSecurityConfig) // 加载校验码配置信息
			.and()
				.apply(smsAuthenticationSecurityConfig)  // 加载短信登录的的配置
			.and()
				.apply(mapleSocialSecurityConfig)  // 加载第三方登录的配置
			.and()
				.rememberMe() // 设置rememberMe配置
					.tokenRepository(persistentTokenRepository)
					.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
					.userDetailsService(userDetailsService)
			.and()
				.sessionManagement()  // session相关配置
					.invalidSessionStrategy(invalidSessionStrategy) // session过期后的处理
					.maximumSessions(securityProperties.getBrowser().getSession().getMaximumSessions()) // 最大登录数
					.maxSessionsPreventsLogin(securityProperties.getBrowser().getSession().isMaxSessionsPreventsLogin()) // 达到最大登录数后，是否阻止后面的登录 
//					.expiredUrl("") // 超出最大登录数跳转的地址
					.expiredSessionStrategy(sessionInformationExpiredStrategy) //超出最大登录数的处理
			.and()
			.and()
				.logout()
					.logoutUrl("/signOut") // 退出的url
//					.logoutSuccessUrl("/maple-signIn.html") // 退出成功后，返回的url
					.logoutSuccessHandler(logoutSuccessHandler)  // 退出的处理
					.deleteCookies("JSESSIONID") // 指定需要删除的cookies的key
			.and()
				.csrf() // csrf防护
				.disable();
		
		// 权限相关的配置
		authorizeConfigManager.config(http.authorizeRequests());
		
	}

}
