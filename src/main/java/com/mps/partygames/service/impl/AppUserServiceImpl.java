package com.mps.partygames.service.impl;

import com.mps.partygames.dto.AppUserDto;
import com.mps.partygames.dto.LoginRequestDto;
import com.mps.partygames.model.AppUser;
import com.mps.partygames.repo.AppUserRepository;
import com.mps.partygames.security.JwtTokenProvider;
import com.mps.partygames.service.AppUserService;
import com.mps.partygames.util.CopyUtil;
import com.mps.partygames.util.JwtConstants;
import com.mps.partygames.util.UserUtil;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AppUserServiceImpl implements AppUserService {
    private final ModelMapper modelMapper;
    @Autowired
    private AppUserRepository appUserRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider tokenProvider;

    AppUserServiceImpl() {
        modelMapper = new ModelMapper();
    }

    @Override
    public String registerUser(AppUserDto dto) {
        if (!UserUtil.isValidEmail(dto.getEmail())) {
            throw new IllegalStateException("Invalid university email");
        }

        // Map from DTO -> Entity
        AppUser appUser = modelMapper.map(dto, AppUser.class);
        appUser.setPassword(passwordEncoder.encode(dto.getPassword()));
        appUser.setEnabled(true);
        // Save the entity
        appUserRepo.saveAndFlush(appUser);

        // Authenticate and return the jwt
        LoginRequestDto loginRequest = new LoginRequestDto(dto.getUsername(), dto.getPassword());

        return authenticate(loginRequest);
    }

    @Override
    public void updateUser(AppUserDto dto, String username) {
        AppUser updateRequest = modelMapper.map(dto, AppUser.class);
        // Get the current appUser
        AppUser currentUser = (AppUser) loadUserByUsername(username);
        // Copy all non-null properties from request -> appUser
        CopyUtil.copyNonNull(updateRequest, currentUser);
        appUserRepo.save(currentUser);
    }

    @Override
    public void deactivateUser(String username) {
        AppUser user = (AppUser) loadUserByUsername(username);
        user.setEnabled(false);
        appUserRepo.save(user);
    }

    @Override
    public AppUser getCurrentUser() {
        return (AppUser) loadUserByUsername(getCurrentUsername());
    }

    @Override
    public List<AppUserDto> getAllUsers() {
        List<AppUser> users = appUserRepo.findAllByEnabledTrue();
        return users.stream()
                .map(user -> modelMapper.map(user, AppUserDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public String getCurrentUsername() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username;
        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else {
            username = principal.toString();
        }
        return username;
    }

    @Override
    public String authenticate(LoginRequestDto dto) {
        UserDetails user = loadUserByUsername(dto.getUsername());
        if (!user.isEnabled()) {
            throw new IllegalStateException("User disabled");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);
        return jwt;
    }

    @Override
    public String refreshToken(String currentToken) {
        currentToken = currentToken.replace(JwtConstants.TOKEN_PREFIX, "");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!tokenProvider.validateToken(currentToken, getCurrentUser())) {
            throw new IllegalStateException("Invalid token");
        }
        return tokenProvider.generateToken(auth);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
