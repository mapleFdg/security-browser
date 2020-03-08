package com.maple.security.browser;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 浏览器配置接口，可通过集成此接口对浏览器进行其他的安全配置
 * 
 * @author hzc
 *
 */
public interface BrowserSecurityConfigCallback {

	void config(HttpSecurity http);

}
