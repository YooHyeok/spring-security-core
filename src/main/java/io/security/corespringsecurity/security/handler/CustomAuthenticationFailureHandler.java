package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Security의 FailureHandler() 인증 실패 이후 작동할 클래스 직접 구현 <br/>
 * SimpleUrlAuthenticationFailureHandler 상속받아서 구현 <br/>
 * 사용자가 로그인 인증 도중 발생하는 Exception에 따라 메시지를 변경처리한다. <br/>
 * 변경된 메세지는 url 파라미터로 넘겨서 처리한다. <br/>
 */
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = exception.getMessage();

        // 예외 타입에 따라 예외 메시지 지정
        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid Secret Key";
        }

        //로그인 파라미터로 예외 메시지 전달.
        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);
        super.onAuthenticationFailure(request,response,exception); //부모클래스로 redierct 처리 위임
    }
}
