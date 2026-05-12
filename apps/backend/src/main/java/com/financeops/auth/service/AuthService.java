package com.financeops.auth.service;

import com.financeops.auth.dto.AuthResponse;
import com.financeops.auth.dto.LoginRequest;
import com.financeops.auth.dto.SignupRequest;
import com.financeops.auth.exception.AuthenticationException;
import com.financeops.auth.exception.UserAlreadyExistsException;
import com.financeops.auth.exception.UserNotFoundException;
import com.financeops.auth.model.User;
import com.financeops.auth.repository.UserRepository;
import com.financeops.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse signup(SignupRequest request) {
        log.info("Processing signup request for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException("Email already registered");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        User savedUser = userRepository.save(user);
        log.info("User registered successfully: {}", savedUser.getEmail());

        String accessToken = jwtService.generateAccessToken(
                new UsernamePasswordAuthenticationToken(savedUser.getEmail(), null)
        );
        String refreshToken = jwtService.generateRefreshToken(savedUser.getEmail());

        return buildAuthResponse(accessToken, refreshToken, savedUser);
    }

    public AuthResponse login(LoginRequest request) {
        log.info("Processing login request for email: {}", request.getEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new UserNotFoundException("User not found"));

            String accessToken = jwtService.generateAccessToken(authentication);
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());

            log.info("User logged in successfully: {}", user.getEmail());
            return buildAuthResponse(accessToken, refreshToken, user);

        } catch (org.springframework.security.core.AuthenticationException e) {
            log.warn("Authentication failed for email: {}", request.getEmail());
            throw new AuthenticationException("Invalid email or password", e);
        }
    }

    public AuthResponse refreshToken(String refreshToken) {
        log.info("Processing token refresh request");

        if (!jwtService.validateToken(refreshToken)) {
            log.warn("Invalid or expired refresh token");
            throw new AuthenticationException("Invalid or expired refresh token");
        }

        String email = jwtService.getEmailFromToken(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(
                new UsernamePasswordAuthenticationToken(email, null)
        );
        String newRefreshToken = jwtService.generateRefreshToken(email);

        log.info("Token refreshed successfully for user: {}", email);
        return buildAuthResponse(newAccessToken, newRefreshToken, user);
    }

    public AuthResponse getCurrentUser(String email) {
        log.info("Fetching current user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // Generate new tokens for "me" endpoint
        String accessToken = jwtService.generateAccessToken(
                new UsernamePasswordAuthenticationToken(email, null)
        );
        String refreshToken = jwtService.generateRefreshToken(email);

        return buildAuthResponse(accessToken, refreshToken, user);
    }

    private AuthResponse buildAuthResponse(String accessToken, String refreshToken, User user) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiry())
                .user(AuthResponse.UserInfoDto.builder()
                        .id(user.getId())
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .role(user.getRole().name())
                        .build())
                .build();
    }
}
