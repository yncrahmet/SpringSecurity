package com.ahmetyeniceri.spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.httpBasic(Customizer.withDefaults());

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/hello").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

}
