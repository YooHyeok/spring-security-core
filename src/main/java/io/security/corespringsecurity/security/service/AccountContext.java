package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * formLogin방식에서 CustomUserDetails 클래스의 loadByUsername()에 의해 <br/>
 * 로그인을 처리할때 로그인 할 사용자 정보를 반환할때 사용하는 클래스이다. <br/>
 * UserDetails를 상속받은 User 클래스를 다시 상속받는다. <br/>

 */
public class AccountContext extends User {
    private final Account account;

    /**
     * 생성자를 통해 Account 회원정보와 권한정보를 함께 관리한다. <br/>
     * formLogin 기능과 관련된 loadByUsername 메소드의 반환타입으로 반환된다. <br/>
     * 반환될때 AccountContext객체는 UserDetails타입으로 업캐스팅 된다.
     */
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
