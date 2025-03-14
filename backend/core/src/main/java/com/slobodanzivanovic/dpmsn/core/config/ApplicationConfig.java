package com.slobodanzivanovic.dpmsn.core.config;

import com.slobodanzivanovic.dpmsn.core.repository.auth.UserRepository;
import com.slobodanzivanovic.dpmsn.core.security.jwt.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.regex.Pattern;

/**
 * Configuration class for core application settings and beans.
 * <p>
 * This class provides configuration for authentication-related components including
 * UserDetailsService, authentication providers, password encoding, and authentication managers.
 * It handles user identification by either username or email pattern.
 * </p>
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

	private final UserRepository userRepository;

	/**
	 * Configures and provides the UserDetailsService implementation.
	 * <p>
	 * This service is used by Spring Security to load user-specific data during authentication.
	 * It supports authentication by either email or username by checking the format of the
	 * provided identifier.
	 * </p>
	 *
	 * @return A UserDetailsService implementation that loads users from the database
	 */
	@Bean
	UserDetailsService userDetailsService() {
		return identifier -> {
			String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
			Pattern pattern = Pattern.compile(emailRegex);
			if (pattern.matcher(identifier).matches()) {
				return userRepository.findByEmail(identifier)
					.map(CustomUserDetails::new)
					.orElseThrow(() -> new UsernameNotFoundException("User not found: " + identifier));
			} else {
				return userRepository.findByUsername(identifier)
					.map(CustomUserDetails::new)
					.orElseThrow(() -> new UsernameNotFoundException("User not found: " + identifier));
			}
		};
	}

	/**
	 * Provides a password encoder for secure password handling.
	 *
	 * @return A BCryptPasswordEncoder instance for password hashing
	 */
	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * Configures the authentication manager.
	 *
	 * @param config The authentication configuration
	 * @return The configured authentication manager
	 * @throws Exception If an error occurs during configuration
	 */
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	/**
	 * Configures and provides the authentication provider.
	 * <p>
	 * This authentication provider uses the custom UserDetailsService and
	 * password encoder to authenticate users.
	 * </p>
	 *
	 * @return The configured authentication provider
	 */
	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());

		return authenticationProvider;
	}

}
