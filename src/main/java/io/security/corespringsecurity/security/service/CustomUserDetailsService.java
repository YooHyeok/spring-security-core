package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * formLogin기능을 통해 로그인을 하기 위한 클래스 <br/>
 * SecurityConfig 설정파일의 configure() 메소드에서 AuthenticationManagerBuilder에 의해 설정된다. <br/>
 * UserDetailsService 인터페이스를 구현한다. <br/>
 * (loadUserByUsername 메소드 구현) <br/>
 * SpringSecurity는 기본적으로 UserDetailsService를 통해 <br/>
 * 회원 아이디와 권한을 파악하여 로그인 할 수 있다. <br/>
 * 현재 클래스는 User에대한 Entity와 Repository등을 <br/>
 * 직접 만들어서 사용하기 위해 커스터마이징 한 클래스이다.
 *
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    /**
     * formLogin방식을 사용할때 호출되는 메소드이다. <br/>
     * 메소드 내부에 구현된 로직에 의해 회원 정보를 반환한다. <br/>
     * [WebSecurityConfigurerAdapter] 필터 내부에서 해당 메소드가 호출되어 <br/>
     * 반환된 회원 정보를 로그인처리가 된다. <br/>
     * @see WebSecurityConfigurerAdapter
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);


        if(account == null) { // null이면 Exception 예외 오류
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }
        /* 권한정보 생성 */
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));

        AccountContext accountContext = new AccountContext(account, roles);
        return accountContext;
    }
}
