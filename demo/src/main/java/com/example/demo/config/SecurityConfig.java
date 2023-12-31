package com.example.demo.config;

import com.example.demo.security.AuthService;
import com.example.demo.security.AuthServiceImpl;
import com.example.demo.security.JwtAuthenticationFilter;
import com.example.demo.security.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Import({AuthenticationConfiguration.class, WebSecurityConfig.class})
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter authenticationFilter(JwtService service) {
        return new JwtAuthenticationFilter(service);
    }

    @Bean
    public JwtService jwtService() {
        return new JwtService();
    }

    @Bean
    public AuthService authService(){
        return new AuthServiceImpl();
    }
}
