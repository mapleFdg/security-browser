package com.maple.security.browser.authentication;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;
import com.maple.security.core.properties.LoginType;
import com.maple.security.core.properties.SecurityProperties;

@Component("mapleAuthenticationSuccessHandler")
public class MapleAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private Logger log = LoggerFactory.getLogger(MapleAuthenticationSuccessHandler.class);

	@Autowired
	private SecurityProperties securityProperties;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		log.info("登录成功，登录用户：" + JSONObject.toJSONString(authentication, true));

		if (LoginType.JSON.equals(securityProperties.getBrowser().getLoginType())) {
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
			super.onAuthenticationSuccess(request, response, authentication);
		}

	}

}
