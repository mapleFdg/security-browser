package com.maple.security.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.maple.security.core.properties.SecurityProperties;

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
