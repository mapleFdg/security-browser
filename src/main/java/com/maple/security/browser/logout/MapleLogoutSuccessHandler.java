package com.maple.security.browser.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.support.SimpleResponse;

/**
 * 
 * 退出登录成功处理器
 * 
 * @author hzc
 *
 */
public class MapleLogoutSuccessHandler implements LogoutSuccessHandler {

	private static final Logger log = LoggerFactory.getLogger(MapleLogoutSuccessHandler.class);

	/**
	 * 系统配置
	 */
	private SecurityProperties securityProperties;

	/**
	 * 转发策略
	 */
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private ObjectMapper objectMapper = new ObjectMapper();

	public MapleLogoutSuccessHandler(SecurityProperties securityProperties) {
		this.securityProperties = securityProperties;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		log.info("退出登录成功");

		String signOutUrl = securityProperties.getBrowser().getSignOutUrl();

		if (StringUtils.isNotBlank(signOutUrl)) {
			redirectStrategy.sendRedirect(request, response, signOutUrl);
		} else {
			response.setContentType("application/json;charset=utf-8");
			response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse("退出成功")));
		}

	}

}
