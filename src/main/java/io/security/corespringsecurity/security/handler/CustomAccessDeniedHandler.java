package io.security.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 현재 사용자가 접근하고자 하는 자원에 인증/인가가 되지 않았을 경우 <br/>
 * 즉, 자원 접근 권한이 없을경우 처리하는 클래스 <br/>
 * AccessDeniedHandler를 구현하는 구현체 클래스이다. <br/>
 * 해당 자원에 접근할 수 없다는 메시지를 URL의 파라미터를 통해 넘긴다.
 */
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private String errorPage;

    /**
     * 빈으로 등록하는 메소드에서 호출된다.
     * 즉, accessDeniedHandler()에 의해 빈이 주입될때 url을 넘겨받는다.
     */
    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 현재 사용자가 접근하고자 하는 자원의 접근할 수 없다는 메시지를 페이지에 뿌리도록 처리
        String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
        response.sendRedirect(deniedUrl);
    }
}
