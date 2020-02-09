package com.maple.security.browser;

import java.sql.Date;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.maple.security.browser.authentication.MapleAuthenticationSuccessHandler;
import com.maple.security.core.authentication.mobile.SmsAuthenticationFilter;
import com.maple.security.core.authentication.mobile.SmsAuthenticationProvider;
import com.maple.security.core.authentication.mobile.SmsAuthenticationSecurityConfig;
import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.validate.code.ValidateCodeFilter;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
	
	/**
	 * 系统配置
	 */
	@Autowired
	private SecurityProperties securityProperties;
	
	/**
	 * 验证成功处理器
	 */
	@Autowired
	private AuthenticationSuccessHandler mapleAuthenticationSuccessHandler;
	
	/**
	 * 验证失败处理器
	 */
	@Autowired
	private AuthenticationFailureHandler mapleAuthenticationFailureHandler;
	
	/**
	 * 验证码校验过滤器
	 */
	@Autowired
	private ValidateCodeFilter validateCodeFilter;
	
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
	
	@Autowired
	private SmsAuthenticationSecurityConfig smsAuthenticationSecurityConfig;
	
	/**
	 * 声明加密方法
	 * @return
	 */
	@Bean
	public PasswordEncoder getPasswordEncod() {
		return new BCryptPasswordEncoder();
	}
	
	/**
	 * 声明一个token的存取器
	 * @return
	 */
	@Bean
	public PersistentTokenRepository getPersistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		// 配置是否在项目启动时创建表
//		tokenRepository.setCreateTableOnStartup(true);
		return tokenRepository;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
			.formLogin()
				.loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
				.loginProcessingUrl(SecurityConstants.DEFAULT_SIGN_IN_PROCESSING_URL_FORM)
				.successHandler(mapleAuthenticationSuccessHandler)
				.failureHandler(mapleAuthenticationFailureHandler)
			.and()
				.rememberMe()
					.tokenRepository(getPersistentTokenRepository())
					.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
					.userDetailsService(userDetailsService)
			.and()
				.authorizeRequests()
				.antMatchers(
						securityProperties.getBrowser().getLoginPage(), 
						SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
						SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*"
					)
				.permitAll()
				.anyRequest()
				.authenticated()
			.and()
				.csrf()
				.disable()
			.apply(smsAuthenticationSecurityConfig);
		
	}

}
