package com.maple.security.browser.authentication;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import com.maple.security.core.properties.LoginResponseType;
import com.maple.security.core.properties.SecurityProperties;

/**
 * 浏览器环境下登录成功的处理器
 * 
 * @author hzc
 *
 */
@Component("mapleAuthenticationSuccessHandler")
public class MapleAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private Logger log = LoggerFactory.getLogger(MapleAuthenticationSuccessHandler.class);

	@Autowired
	private SecurityProperties securityProperties;

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		//log.warn("默认的退出处理逻辑，若有需求，可实现接口SimpleUrlAuthenticationSuccessHandler以覆盖默认配置");
		
		log.info(authentication.getName() + " --> 登录成功"  );

		if (LoginResponseType.JSON.equals(securityProperties.getBrowser().getLoginType())) {
			String targetUrl = determineTargetUrl(request, response);
			String name = authentication.getName();
			Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
			JSONObject resultJson = new JSONObject();
			resultJson.put("targetUrl", targetUrl);
			resultJson.put("name", name);
			resultJson.put("authorities", authorities);

			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(resultJson.toJSONString());
		} else {
			// 如果设置了imooc.security.browser.singInSuccessUrl，总是跳到设置的地址上
			// 如果没设置，则尝试跳转到登录之前访问的地址上，如果登录前访问地址为空，则跳到网站根路径上
			if (StringUtils.isNotBlank(securityProperties.getBrowser().getSignInSuccessUrl())) {
				requestCache.removeRequest(request, response);
				setAlwaysUseDefaultTargetUrl(true);
				setDefaultTargetUrl(securityProperties.getBrowser().getSignInSuccessUrl());
			}
			super.onAuthenticationSuccess(request, response, authentication);
		}

	}

}
