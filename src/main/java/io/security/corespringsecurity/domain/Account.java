package io.security.corespringsecurity.domain;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/** 회원 가입을 위한 DB와 매핑될 Account Entity클래스 */
@Entity
@Data
public class Account {
    @Id @GeneratedValue
    private Long Id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
