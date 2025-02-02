package com.maple.security.browser.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.maple.security.core.properties.LoginResponseType;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.support.SimpleResponse;

/**
 * 浏览器环境下登录失败的处理器
 * 
 * @author hzc
 *
 */
@Component("mapleAuthenticationFailureHandler")
public class MapleAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private Logger log = LoggerFactory.getLogger(MapleAuthenticationSuccessHandler.class);

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private ObjectMapper objectMapper;
	
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		log.info("登录失败，失败信息：" + exception.getMessage());

		if (securityProperties.getBrowser().getLoginType() == LoginResponseType.JSON) {
			response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(exception.getMessage())));
		} else {
			super.onAuthenticationFailure(request, response, exception);
		}

	}

}
