package com.maple.security.browser;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.social.security.SpringSocialConfigurer;

import com.maple.security.core.authentication.AbstractChannelSecurityConfig;
import com.maple.security.core.authentication.mobile.SmsAuthenticationSecurityConfig;
import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * browser 配置类
 * 
 * @author hzc
 *
 */
@Configuration
public class BrowserSecurityConfig extends AbstractChannelSecurityConfig {
	
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
	 * 数据源
	 */
	@Autowired
	private DataSource dataSource;
	
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
	 * 声明加密方法
	 * @return
	 */
	@Bean
	public PasswordEncoder passwordEncod() {
		return new BCryptPasswordEncoder();
	}
	
	/**
	 * 声明一个token的存取器
	 * @return
	 */
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		// 配置是否在项目启动时创建表
//		tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		applyPasswordAuthenticationConfig(http);
		
		http.apply(validateCodeSecurityConfig) // 加载校验码配置信息
			.and()
				.apply(smsAuthenticationSecurityConfig)  // 加载短信登录的的配置
			.and()
				.apply(mapleSocialSecurityConfig)  // 加载第三方登录的配置
			.and()
				.rememberMe() // 设置rememberMe配置
					.tokenRepository(persistentTokenRepository())
					.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
					.userDetailsService(userDetailsService)
			.and()
				.authorizeRequests() // 配置拦截的请求
				.antMatchers(
						securityProperties.getBrowser().getLoginPage(), 
						SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
						SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*",
						securityProperties.getBrowser().getSignUpUrl(),
						"/hello"
					) // 排除掉哪些请求
				.permitAll()
				.anyRequest()
				.authenticated()
			.and()
				.csrf() // csrf防护
				.disable();
	}

}
