package io.security.corespringsecurity.security.handler;


import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security의 SucessHandler() 인증 성공 이후 작동할 클래스 직접 구현 <br/>
 * SimpleUrlAuthenticationSuccessHandler 상속받아서 구현 <br/>
 * 사용자가 로그인 인증 전에 어떤 요청을 하였는지에 대한 객체를 기준으로 <br/>
 * 객체가 비어있지 않다면 해당 정보로부터 요청 url을 꺼내와 redirect <br/>
 * 객체가 비어 있다면 루트 경로로 redirect
 */
@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/"); // defaultTargetUrl을 루트경로로 지정

        //URL캐시처리
        SavedRequest savedRequest = requestCache.getRequest(request, response); //사용자가 인증에 성공하기 전 요청 정보들을 담고있는 객체
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
