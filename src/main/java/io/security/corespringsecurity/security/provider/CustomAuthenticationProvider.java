package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.CustomWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 로그인 인증 검증 Customizing 클래스 <br/>
 * 일반적으로 로그인 인증에 대한 검증은 SpringSecurity의 AuthenticationProvider에 의해서 검증된다 <br/>
 * AuthenticationProvider 메소드들은 AuthenticationManager에게 반환한다.
 * 따라서 AuthenticationProvider 인터페이스를 구현한 뒤, Config파일에 빈으로 등록하여 사용한다. <br/>
 */
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 로그인 인증 검증을 위한 authenticate 메소드 구현
     * Authendtication객체는 AuthenticationManager 클래스로부터 전달받는 인증객체이다. <br/>
     * 사용자가 입력한 ID, PASSWORD 정보가 담겨있다 <br/>
     * 해당 로그인 요청 정보를 통해 DB에 저장된 사용자의 패스워드 일치여부를 진행하고
     * 일치할 경우 UsernamePasswordAuthenticationToken 토큰 객체에 사용자 정보와, 권한정보를 담아 반환한다.
     * AuthenticationProvider를 호출한 ProviderManager에게 반환한다. <br/>
     * 최종적으로 ProviderManager에서 AuthenticationProvicer 메소드를 구현하여 authenticate메소드를 호출한다. <br/>
     * 그 메소드 안에서 호출되는 authenticate()메소드는 SecurityConfig로 현재 커스텀 클래스객체가 <br/>
     * AuthenticationProvider타입으로 @빈 등록 주입 되었기 때문에 이 메소드의 로직이 실행된다.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            // 사용자가 입력한 패스워드와 DB에 암호화된 패스워드 일치 여부
            throw new BadCredentialsException("BadCredentialsException");//일치하지 않으면 예외 발생
        }

        CustomWebAuthenticationDetails formWebAuthenticationDetails = (CustomWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        // 사용자 정보를 담은 객체(principal), 비밀번호(cridential),  권한정보
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(
                        accountContext.getAccount()
                , null // 비밀번호 검증을 했기 때문에 null로 처리한다(?)
                , accountContext.getAuthorities());
        /**
         * 비밀번호를 null로 설정하는 이유
         * SpringSecurity에서는 내부적으로 Authentication 객체에 있는
         * credential속성에 값을 저장하지 않고 null로 설정하고 있다.
         * 꼭 필요로 한다면 값을 저장해도 된다.
         * 다만 보안에 취약하지 않도록 적절한 처리가 필요할 수 있다.
         * Authentication 객체의 경우 일반적으로 객체의 전체 값을
         * 클라이언트로 전달하는 경우도 있기 때문에 패스워드 같은 값은 제외하는것이 안전하다.
         */

        return authenticationToken;
    }
    /**
     * AuthenticationProvider의 메소드이다.
     * 매개변수로 받는 authentication 클래스의 타입과 <br/>
     * CustomAuthenticationProvider클래스가 사용하는 토큰의 타입이 서로 일치할 때 <br/>
     * provider가 인증처리 할수 있도록 하는 메소드이다. <br/>
     * 내부적으로 ProviderManager에 의해 호출되어 처리된다.
     * */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class
                .isAssignableFrom(authentication); //토큰이 클래스 타입과 일치할 때 CustomAuthenticationProvider가 인증을 처리하도록
    }
}
