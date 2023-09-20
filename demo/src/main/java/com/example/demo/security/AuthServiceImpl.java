package com.example.demo.security;

import com.example.demo.user.CustomUser;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;


public class AuthServiceImpl implements AuthService {
    @Override
    public UUID getAuthorizedUserId() {
        CustomUser userDetails = (CustomUser) SecurityContextHolder.getContext()
                                                                   .getAuthentication()
                                                                   .getDetails();
        return userDetails.getId();

    }
}
