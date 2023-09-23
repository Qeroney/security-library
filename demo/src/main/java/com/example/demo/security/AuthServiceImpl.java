package com.example.demo.security;

import com.example.demo.user.CustomUserDetails;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;


public class AuthServiceImpl implements AuthService {
    @Override
    public UUID getAuthorizedUserId() {
        CustomUserDetails userDetails = (CustomUserDetails) SecurityContextHolder.getContext()
                                                                                 .getAuthentication()
                                                                                 .getDetails();
        return userDetails.getId();

    }
}
