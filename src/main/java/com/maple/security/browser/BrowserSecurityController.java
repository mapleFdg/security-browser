package com.maple.security.browser;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.social.SocialController;
import com.maple.security.core.social.support.SocialUserInfo;
import com.maple.security.core.support.SimpleResponse;

/**
 * 浏览器环境下与安全相关的服务
 * 
 * @author hzc
 *
 */
@RestController
public class BrowserSecurityController extends SocialController {

	private Logger log = LoggerFactory.getLogger(BrowserSecurityController.class);

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Autowired
	private SecurityProperties securityProperties;
	@Autowired
	private ProviderSignInUtils providerSignInUtils;

	/**
	 * 当需要身份认证时，跳转到这里
	 * 
	 * @param request
	 * @param response
	 * @return
	 * @throws IOException
	 */
	@RequestMapping(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public SimpleResponse requireAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws IOException {

		log.info("请求需要先进行认证");

		SavedRequest savedRequest = requestCache.getRequest(request, response);

		if (savedRequest != null) {
			String targetUrl = savedRequest.getRedirectUrl();

			log.info("需要进行跳转的url为：" + targetUrl);

			if (StringUtils.endsWithIgnoreCase(targetUrl, ".html")) {
				log.info("请求为页面的请求，需要跳转到登录的页面");

				redirectStrategy.sendRedirect(request, response, securityProperties.getBrowser().getLoginPage());

				log.info("跳转到了登录页面，登录页面为：" + securityProperties.getBrowser().getLoginPage());

				return null;
			} else {
				log.info("请求为api的请求，返回JSON");
				return new SimpleResponse("访问的服务需要身份认证，请引导用户到登录页");
			}
		}
		return null;
	}

	/**
	 * 用户第一次社交登录时，会引导用户进行用户注册或绑定，此服务用于在注册或绑定页面获取社交网站用户信息
	 * 
	 * @param request
	 * @return
	 */
	@GetMapping(SecurityConstants.DEFAULT_SOCIAL_USER_INFO_URL)
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		Connection<?> connection = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
		return buildSocialUserInfo(connection);
	}

	@GetMapping("/session/invalid")
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public SimpleResponse sessionInvalid() {
		String message = "session失效";
		return new SimpleResponse(message);
	}

}
