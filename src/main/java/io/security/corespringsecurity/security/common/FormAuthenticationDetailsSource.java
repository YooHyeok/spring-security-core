package io.security.corespringsecurity.security.common;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.http.HttpRequest;

/**
 * AuthnticationDetailsSource의 buildDetails()메소드는 Security내부적으로 Form인증시 필요한 Details객체를 생성한다.
 * Details객체에는 SessionId와 사용자 정보를 담고 있다.
 * 해당 객체는 WebAuthenticationDetails 클래스 타입으로 반환된다.
 * AuthenticationDetailsSource 인터페이스는 WebAuthenticationDetailsSource 구현체 클래스에서 구현된다.
 * 추가적인 파라미터 데이터를 받아서 처리하기 위해 WebAuthenticationDetailsSource이 아닌 현재 클래스를 사용하여 구현한다.
 * buildDetails 메소드에 우리가 직접 만든 FormWebAuthenticationDetails 클래스 객체로 반환한다.
 */
@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new FormWebAuthenticationDetails(context);
    }
}
