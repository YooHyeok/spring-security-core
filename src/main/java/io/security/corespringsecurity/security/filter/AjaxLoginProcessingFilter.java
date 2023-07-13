package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * AbstractAuthenticationProcessingFilter 추상클래스는 대부분의 인증처리 기능을 담고있다.
 * 따라서 해당 클래스를 상속받아서 Ajax Filter 구현한다.
 *
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 사용자가 URL로 요청을 했을 때
     */
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login")); //해당 URL로 요청이 오면 생성자가 작동된다.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        /**
         * Ajax통신이 아니면 Exception발생
         */
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        /**
         * Ajax이면 request 정보를 DTO객체로 반환한다.
         */
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        /**
         * 반환받은 DTO객체의 Username과 Password 둘중 하나가 비어있다면 Exception발생
         */
        if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is Empty");
        }

        /**
         * 요청 정보중 id와 password가 비어있지 않으면 Ajax인가토큰 객체를 반환한다.
         * setAuthenticated()에 의해
         */
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        /**
         * 반환된 인가토큰 객체를 반환한다.
         */
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    /**
     * Ajax 통신 여부 확인 메소드
     * @return Boolean형태로 반환한다. Ajax면 True 아니면 False
     */
    private boolean isAjax(HttpServletRequest request) {
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }
        return false;
    }
}
