package com.boris.spring.login.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.boris.spring.login.models.RefreshToken;
import com.boris.spring.login.models.User;


@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
  Optional<RefreshToken> findByToken(String id);


  long deleteByUser(User user);
}
