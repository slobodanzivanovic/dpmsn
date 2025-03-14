package com.slobodanzivanovic.dpmsn.core.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Configuration class for OAuth2 client integration.
 * <p>
 * This class provides configuration for OAuth2 authentication.
 * </p>
 */
@Configuration
public class OAuth2ClientConfig {

	@Value("${oauth2.client.google.client-id}")
	private String googleClientId;

	@Value("${oauth2.client.google.client-secret}")
	private String googleClientSecret;

	@Value("${oauth2.client.github.client-id}")
	private String githubClientId;

	@Value("${oauth2.client.github.client-secret}")
	private String githubClientSecret;

	/**
	 * Configures and provides the ClientRegistrationRepository.
	 * <p>
	 * This repository holds the client registrations for different OAuth2 providers.
	 * </p>
	 *
	 * @return A configured ClientRegistrationRepository containing all supported OAuth2 providers
	 */
	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(
			googleClientRegistration(),
			githubClientRegistration()
		);
	}

	/**
	 * Creates a client registration for Google OAuth2 authentication.
	 *
	 * @return A configured ClientRegistration for Google
	 */
	private ClientRegistration googleClientRegistration() {
		return ClientRegistration.withRegistrationId("google")
			.clientId(googleClientId)
			.clientSecret(googleClientSecret)
			.scope("openid", "profile", "email")
			.authorizationUri("https://accounts.google.com/o/oauth2/auth")
			.tokenUri("https://oauth2.googleapis.com/token")
			.clientName("Google")
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
			.userNameAttributeName("sub")
			.build();
	}

	/**
	 * Creates a client registration for GitHub OAuth2 authentication.
	 * <p>
	 * Note: GitHub may not always return email information directly, which may
	 * require additional API calls to retrieve user emails.
	 * </p>
	 *
	 * @return A configured ClientRegistration for GitHub
	 */
	private ClientRegistration githubClientRegistration() {
		return ClientRegistration.withRegistrationId("github")
			.clientId(githubClientId)
			.clientSecret(githubClientSecret)
			.scope("read:user", "user:email")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.clientName("GitHub")
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.userNameAttributeName("login")
			.build();
	}

}
