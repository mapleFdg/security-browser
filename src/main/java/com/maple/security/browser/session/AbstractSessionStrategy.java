package com.maple.security.browser.session;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.maple.security.browser.support.SimpleResponse;
import com.maple.security.core.properties.SecurityProperties;

public class AbstractSessionStrategy {
 
	private final static Logger log = LoggerFactory.getLogger(AbstractSessionStrategy.class);
	
	/**
	 * 需要跳转的url
	 */
	private String destinationUrl;
	
	/**
	 * 系统配置信息
	 */
	private SecurityProperties securityProperties;
	
	/**
	 * 重定向策略
	 */
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	/**
	 * 是否创建新的session
	 */
	private boolean createNewSession = true;
	
	private ObjectMapper objectMapper = new ObjectMapper();
	
	public AbstractSessionStrategy(SecurityProperties securityProperties) {
		String invalidUrl = securityProperties.getBrowser().getSession().getSessionInvalidUrl();
		// 判断url是否合法，否则抛出异常
		Assert.isTrue(UrlUtils.isValidRedirectUrl(invalidUrl),"url 必须以“/”或者“http(s)”开头");
		Assert.isTrue(StringUtils.endsWithIgnoreCase(invalidUrl, ".html"), "url 唏嘘以“.html”结尾");
		this.securityProperties = securityProperties;
		this.destinationUrl = invalidUrl;
	}
	
	
	protected void onSessionInvalid(HttpServletResponse response, HttpServletRequest request) throws IOException {
		
		log.info("session失效");
		
		if(createNewSession) {
			request.getSession();
		}
		
		String sourceUrl = request.getRequestURI();
		String targetUrl;
		
		if(StringUtils.endsWithIgnoreCase(sourceUrl, ".html")) {
			if(StringUtils.equals(sourceUrl, securityProperties.getBrowser().getLoginPage())){
				targetUrl = sourceUrl;
			}else{
				targetUrl = destinationUrl;
			}
			log.info("跳转到:"+targetUrl);
			redirectStrategy.sendRedirect(request, response, targetUrl);
		}else {
			Object result = buildResponseContent(request);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(result));
		}
		
		
	}

	/**
	 * @param request
	 * @return
	 */
	protected Object buildResponseContent(HttpServletRequest request) {
		String message = "session已失效";
		if (isConcurrency()) {
			message = message + "，有可能是并发登录导致的";
		}
		return new SimpleResponse(message);
	}

	/**
	 * session失效是否是并发导致的
	 * 
	 * @return
	 */
	protected boolean isConcurrency() {
		return false;
	}

	/**
	 * Determines whether a new session should be created before redirecting (to
	 * avoid possible looping issues where the same session ID is sent with the
	 * redirected request). Alternatively, ensure that the configured URL does
	 * not pass through the {@code SessionManagementFilter}.
	 *
	 * @param createNewSession
	 *            defaults to {@code true}.
	 */
	public void setCreateNewSession(boolean createNewSession) {
		this.createNewSession = createNewSession;
	}
	
}
