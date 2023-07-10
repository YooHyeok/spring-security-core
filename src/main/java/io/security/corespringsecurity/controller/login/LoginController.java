package io.security.corespringsecurity.controller.login;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "user/login/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        /* 인증객체 획득 */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        /* 로그아웃 처리 */
        if (authentication != null) { //인증객체가 null이아니면 실행
           new SecurityContextLogoutHandler().logout(request,response,authentication); //로그아웃 처리
            /**
             * SecurityContextLogoutHandler : Security내부에서 로그아웃을 처리해주는 핸들러
             */
        }
        return "redirect:/login";
    }
}
