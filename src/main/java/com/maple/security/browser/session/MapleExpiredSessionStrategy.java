package com.maple.security.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;

import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.maple.security.core.properties.SecurityProperties;

/**
 * 并发登录导致session失效时，默认的处理策略
 * 
 * @author hzc
 *
 */
public class MapleExpiredSessionStrategy extends AbstractSessionStrategy implements SessionInformationExpiredStrategy{

	public MapleExpiredSessionStrategy(SecurityProperties securityProperties) {
		super(securityProperties);
	}

	@Override
	public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
		super.onSessionInvalid(event.getResponse(), event.getRequest());
	}

	@Override
	protected boolean isConcurrency() {
		return true;
	}
	
}
