package com.example.demo.security;

import java.util.UUID;

public interface AuthService {
    UUID getAuthorizedUserId();
}