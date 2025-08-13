package com.vakya.user_service.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginPageController {
    @GetMapping("/login-page")
    public String loginPage() {
        return "login";
    }
    @GetMapping("/success")
    public String successPage() {
        return "succes";
    }
}

