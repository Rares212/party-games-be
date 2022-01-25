package com.mps.partygames.service;

import com.mps.partygames.dto.HostDto;
import com.mps.partygames.dto.LoginRequestDto;
import com.mps.partygames.model.Host;

import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface HostService extends UserDetailsService {
    String registerUser(HostDto dto);
    void updateUser(HostDto dto, String username);
    void deactivateUser(String hostId);
    Host getCurrentUser();
    List<HostDto> getAllUsers();
    String getCurrentUsername();

    String authenticate(LoginRequestDto dto);
    String refreshToken(String currentToken);
}
