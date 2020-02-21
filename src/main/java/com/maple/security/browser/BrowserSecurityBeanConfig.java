package com.maple.security.browser;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.maple.security.browser.logout.MapleLogoutSuccessHandler;
import com.maple.security.browser.session.MapleExpiredSessionStrategy;
import com.maple.security.browser.session.MapleInvalidSessionStrategy;
import com.maple.security.core.properties.SecurityProperties;

/**
 * browser 的bean配置类
 * 
 * @author hzc
 *
 */
@Configuration
public class BrowserSecurityBeanConfig {

	/**
	 * 数据源
	 */
	@Autowired
	private DataSource dataSource;

	/**
	 * 系统配置类
	 */
	@Autowired
	private SecurityProperties securityProperties;

	/**
	 * 声明一个token的存取器
	 * 
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

	/**
	 * 声明一个session超出登录数的处理类
	 * 
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(SessionInformationExpiredStrategy.class)
	public SessionInformationExpiredStrategy sessionInformationExpiredStrategy() {
		return new MapleExpiredSessionStrategy(securityProperties);
	}

	/**
	 * 声明一个session过去的处理
	 * 
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(InvalidSessionStrategy.class)
	public InvalidSessionStrategy invalidSessionStrategy() {
		return new MapleInvalidSessionStrategy(securityProperties);
	}

	/**
	 * 
	 * 声明一个退出成功处理器
	 * 
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(LogoutSuccessHandler.class)
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new MapleLogoutSuccessHandler(securityProperties);
	}

}
