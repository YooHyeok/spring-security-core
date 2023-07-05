package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    //인가 정책 시작
                .authorizeRequests()
                .anyRequest()
                .authenticated()
        .and()  //인증 정책 시작
                .formLogin(); // 기본 인증방식 : FORM Login

    }
}
