package com.maple.security.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.session.InvalidSessionStrategy;

import com.maple.security.core.properties.SecurityProperties;

/**
 * 默认的session失效处理策略
 * 
 * @author hzc
 *
 */
public class MapleInvalidSessionStrategy extends AbstractSessionStrategy implements InvalidSessionStrategy {

	public MapleInvalidSessionStrategy(SecurityProperties securityProperties) {
		super(securityProperties);
	}

	@Override
	public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		super.onSessionInvalid(response, request);
	}

}
