package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;
    //실제 사용시 구현체 FormAuthenticationDetailsSource 객체 주입(반환타입만 인터페이스)
    @Autowired
    private CustomUserDetailsService customUserDetailsService;
//    private UserDetailsService userDetailsService;

    /** 정적 리소스파일 보인필터 해제 */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /** 사용자 등록 */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // 암호화된 방식으로 패스워드 부여
//        String password = passwordEncoder().encode("1234");

        // 인메모리방식 사용자 추가
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER", "USER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "MANAGER", "USER");

//        auth.userDetailsService(userDetailsService);
//        auth.userDetailsService(customUserDetailsService); // UserDetailsService 구현체 CustomUserDetails를 사용해서 로그인하게 된다.
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }


    /**
     * 빈 등록 <br/>
     * 패스워드 인코딩 메소드
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    //인가 정책 시작
                .authorizeRequests()
                // 각 사용자별 접근 페이지 각 경로별 권한 부여
                .antMatchers("/", "/users").permitAll() // 루트, 회원가입 페이지 모든 사용자 인증 및 권한 오픈
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest()
                .authenticated()
        .and()  //인증 정책 시작
                .formLogin() // 기본 인증방식 : FORM Login
                .loginPage("/login") //직접 만든 login페이지로 이동
                .loginProcessingUrl("/login_proc")// 로그인을 처리하는 컨트롤러 매핑주소
                .defaultSuccessUrl("/") //성공시 루트페이지로 이동
                .authenticationDetailsSource(authenticationDetailsSource)//FormAuthenctiontionDetailsSource객체 주입
                .permitAll();

    }
}
