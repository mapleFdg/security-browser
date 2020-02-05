package com.maple.security.browser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.maple.security.browser.authentication.MapleAuthenticationSuccessHandler;
import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.validate.code.ValidateCodeFilter;

@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private SecurityProperties securityProperties;
	
	
	@Autowired
	private AuthenticationSuccessHandler mapleAuthenticationSuccessHandler;
	
	@Autowired
	private AuthenticationFailureHandler mapleAuthenticationFailureHandler;
	
	@Autowired
	private ValidateCodeFilter validateCodeFilter;
	

	@Bean
	public PasswordEncoder getPasswordEncod() {
		return new BCryptPasswordEncoder();
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
				.authorizeRequests()
				.antMatchers(
						securityProperties.getBrowser().getLoginPage(), 
						SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
						"/code/image")
				.permitAll()
				.anyRequest().authenticated().and().csrf().disable();
	}

}
