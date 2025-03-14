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

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

	private final UserRepository userRepository;

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

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		
		return authenticationProvider;
	}

}
