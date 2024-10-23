package com.ahmetyeniceri.spring_security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/hello")
    public String helloWorld(){
        return "Hello World!";
    }

    @GetMapping("/dashboard")
    public String dashBoard(){
        return "Giriş başarılı!";
    }

}
