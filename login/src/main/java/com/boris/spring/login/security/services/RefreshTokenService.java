package com.boris.spring.login.security.services;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.boris.spring.login.exception.TokenRefreshException;
import com.boris.spring.login.models.RefreshToken;
import com.boris.spring.login.models.User;
import com.boris.spring.login.repository.RefreshTokenRepository;
import com.boris.spring.login.repository.UserRepository;;


@Service
public class RefreshTokenService {
  @Value("${spring.app.jwtRefreshExpirationMs}")
  private Long refreshTokenDurationMs;

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;

  @Autowired
  private UserRepository userRepository;

  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  public RefreshToken createRefreshToken(String userId) {
    RefreshToken refreshToken = new RefreshToken();

    User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found with id " + userId));
    refreshToken.setUser(user);
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(UUID.randomUUID().toString());

    refreshToken = refreshTokenRepository.save(refreshToken);
    return refreshToken;
  }

  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
      refreshTokenRepository.delete(token);
      throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
    }

    return token;
  }
  public void deleteByUserId(String userId) {
    // Handling the case where the user might not be found
    User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found with id " + userId));
    refreshTokenRepository.deleteByUser(user);
  }
}
