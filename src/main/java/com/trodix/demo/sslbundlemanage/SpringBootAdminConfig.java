package com.trodix.demo.sslbundlemanage;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SpringBootAdminConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(CsrfConfigurer::disable)
                .authorizeHttpRequests(i -> {
                    i.requestMatchers(AntPathRequestMatcher.antMatcher("/api/**")).permitAll();
                });

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain springBootAdminClientFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/actuator/**")
                .authorizeHttpRequests(i -> {
                    i.requestMatchers(AntPathRequestMatcher.antMatcher("/actuator/**")).authenticated();
                })
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

}
