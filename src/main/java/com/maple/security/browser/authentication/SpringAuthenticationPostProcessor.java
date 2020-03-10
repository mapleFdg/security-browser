package com.maple.security.browser.authentication;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import com.maple.security.core.properties.SecurityProperties;

/**
 * Bean的前后处理
 * 
 * @author hzc
 *
 */
@Component
public class SpringAuthenticationPostProcessor implements BeanPostProcessor{

	@Autowired
	private SecurityProperties securityProperties;
	
	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		
		String signInFailureUrl = securityProperties.getBrowser().getSignInFailureUrl();
		
		// 配置默认的登录失败跳转地址
		if(StringUtils.equals(beanName, "mapleAuthenticationFailureHandler") && StringUtils.isNotBlank(signInFailureUrl)) {
			MapleAuthenticationFailureHandler handler = (MapleAuthenticationFailureHandler)bean;
			handler.setDefaultFailureUrl(signInFailureUrl);
			return handler;
		}
		return bean;
	}

}
