package com.mps.partygames.service.impl;

import com.mps.partygames.dto.HostDto;
import com.mps.partygames.dto.LoginRequestDto;
import com.mps.partygames.model.Host;
import com.mps.partygames.repo.HostRepository;
import com.mps.partygames.security.JwtTokenProvider;
import com.mps.partygames.service.HostService;
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
public class HostServiceImpl implements HostService {
    private final ModelMapper modelMapper;
    @Autowired
    private HostRepository hostRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider tokenProvider;

    HostServiceImpl() {
        modelMapper = new ModelMapper();
    }

    @Override
    public String registerUser(HostDto dto) {
        if (!UserUtil.isValidEmail(dto.getEmail())) {
            throw new IllegalStateException("Invalid university email");
        }

        // Map from DTO -> Entity
        Host host = modelMapper.map(dto, Host.class);
        host.setPassword(passwordEncoder.encode(dto.getPassword()));
        host.setEnabled(true);
        // Save the entity
        hostRepo.saveAndFlush(host);

        // Authenticate and return the jwt
        LoginRequestDto loginRequest = new LoginRequestDto(dto.getUsername(), dto.getPassword());

        return authenticate(loginRequest);
    }

    @Override
    public void updateUser(HostDto dto, String username) {
        Host updateRequest = modelMapper.map(dto, Host.class);
        // Get the current host
        Host currentUser = (Host) loadUserByUsername(username);
        // Copy all non-null properties from request -> host
        CopyUtil.copyNonNull(updateRequest, currentUser);
        hostRepo.save(currentUser);
    }

    @Override
    public void deactivateUser(String username) {
        Host user = (Host) loadUserByUsername(username);
        user.setEnabled(false);
        hostRepo.save(user);
    }

    @Override
    public Host getCurrentUser() {
        return (Host) loadUserByUsername(getCurrentUsername());
    }

    @Override
    public List<HostDto> getAllUsers() {
        List<Host> users = hostRepo.findAllByEnabledTrue();
        return users.stream()
                .map(user -> modelMapper.map(user, HostDto.class))
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
        return hostRepo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
