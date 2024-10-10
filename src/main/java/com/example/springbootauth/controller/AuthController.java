package com.example.springbootauth.controller;

import com.example.springbootauth.util.JwtUtils;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/sign-in")
    public String signIn(@RequestBody SignInReq signInReq) {
        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(signInReq.username, signInReq.password);
        Authentication authenticate = authenticationManager.authenticate(authentication);
        if (authenticate.isAuthenticated()) {
            return jwtUtils.generateToken(signInReq.username);
        }
        throw new UsernameNotFoundException("invalid username/password");
    }

    @GetMapping("/user/user-profile")
    public String user() {
        return "user profile";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin page";
    }

    @GetMapping(path = "ping")
    public boolean ping() {
        return true;
    }

    @Data
    static class SignInReq {
        private String password;
        private String username;
    }
}
