package com.ahmetyeniceri.securitydemo.controller;

import com.ahmetyeniceri.securitydemo.dto.LoginRequest;
import com.ahmetyeniceri.securitydemo.dto.LoginResponse;
import com.ahmetyeniceri.securitydemo.jwt.AuthTokenFilter;
import com.ahmetyeniceri.securitydemo.jwt.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    private static final Logger logger = LoggerFactory.getLogger(GreetingsController.class);

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public GreetingsController(JwtUtils jwtUtils, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/google-callback")
    public Map<String, String> handleGoogleCallback(@RequestParam(value = "email", required = false) String email) {
        if (email == null || email.isEmpty()) {
            throw new IllegalStateException("Email parameter is missing in the redirect URL");
        }

        UserDetails userDetails = User.withUsername(email)
                .password("")
                .authorities("ROLE_USER")
                .build();

        if (userDetailsService instanceof JdbcUserDetailsManager) {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            if (!manager.userExists(email)) {
                manager.createUser(userDetails);
                logger.info("User {} created in the database", email);
            }
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateTokenFromUsername(userDetails);

        Map<String, String> response = new HashMap<>();
        response.put("token", jwt);
        response.put("username", email);
        return response;
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello, User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello, Admin!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication;

        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authentication: " + authentication);

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", userDetails.getUsername());
        profile.put("roles", userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList())
        );
        profile.put("message", "This is user-spesific content form backend");

        return ResponseEntity.ok(profile);
    }

}
