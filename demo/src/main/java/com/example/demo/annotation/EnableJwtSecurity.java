package com.example.demo.annotation;

import com.example.demo.config.SecurityConfig;
import com.example.demo.config.WebSecurityConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Import({WebSecurityConfig.class, SecurityConfig.class})
@Target({ElementType.TYPE})
public @interface EnableJwtSecurity {
}
