package com.slobodanzivanovic.dpmsn.core.service.auth;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.LoginRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.LoginResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public interface AuthenticationService {

	LoginResponse login(LoginRequest loginRequest);

	void logout(String token);

	UserEntity signup(RegisterRequest registerRequest);

	void verifyUser(String email, String verificationCode);

	void resendVerificationCode(String email);

	void requestPasswordReset(String email);

	void resetPassword(String email, String verificationCode, String newPassword);

	String handleOAuthLogin(OAuth2AuthenticationToken authentication);
	
}
