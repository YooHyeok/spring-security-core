package io.security.corespringsecurity.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * WebAuthnticationDetails클래스의 details 객체를 대신한다.
 * FormAuthenticationDetailsSource 클래스에서 buildDetails() 메소드에 의해 반환되는 객체로 사용된다.
 * FormWebAuthenticationDetails는 WebAuthenticationDetails 클래스를 상속받았기 때문에
 * 생성자에서 super(request);를 통해 부모클래스의 기본 필드 값을 초기화한다.
 * 이때 상속의 특징에 의해 자식한테도 동일한 필드가 생성되지만, 반환자체를 부모타입으로 하게되면 자식클래스 필드에 접근이 불가능해진다.
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretKey = request.getParameter("secret_key");
    }

    public String getSecretKey() {
        return secretKey;
    }
}
