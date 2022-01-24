package com.mps.partygames.service;

import com.mps.partygames.dto.AppUserDto;
import com.mps.partygames.dto.LoginRequestDto;
import com.mps.partygames.model.AppUser;

import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface AppUserService extends UserDetailsService {
    String registerUser(AppUserDto dto);
    void updateUser(AppUserDto dto, String username);
    void deactivateUser(String appUserId);
    AppUser getCurrentUser();
    List<AppUserDto> getAllUsers();
    String getCurrentUsername();

    String authenticate(LoginRequestDto dto);
    String refreshToken(String currentToken);
}
