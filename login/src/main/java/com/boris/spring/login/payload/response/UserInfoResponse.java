package com.boris.spring.login.payload.response;

import java.util.List;

public class UserInfoResponse {
  private String id;
  private String username;
  private String email;
  private List<String> roles;
  private String jwt;
  private String refreshTokenValue;

  public UserInfoResponse(String id, String username, String email, List<String> roles, String jwt,
      String refreshTokenValue) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.roles = roles;
    this.jwt = jwt;
    this.refreshTokenValue = refreshTokenValue;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getJWT() {
    return jwt;
  }

  public void setJWT(String jwt) {
    this.jwt = jwt;
  }

  public String getRefreshToken() {
    return refreshTokenValue;
  }

  public void setRefreshToken(String refreshTokenValue) {
    this.refreshTokenValue = refreshTokenValue;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public List<String> getRoles() {
    return roles;
  }
}
