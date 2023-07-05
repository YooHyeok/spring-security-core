package io.security.corespringsecurity.domain;

import lombok.Data;

/** 회원 가입을 위한 Entity와 매핑될 Account Dto클래스 */
@Data
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
