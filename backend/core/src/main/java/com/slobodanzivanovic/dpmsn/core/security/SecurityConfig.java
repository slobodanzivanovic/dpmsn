package com.slobodanzivanovic.dpmsn.core.security;

import com.slobodanzivanovic.dpmsn.core.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final AuthenticationProvider authenticationProvider;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.csrf(AbstractHttpConfigurer::disable)
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/api/v1/auth/**").permitAll()
				.requestMatchers("/actuator/**").permitAll() // for rureka/admin monitoring
				.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll() // add this...

				.requestMatchers("/api/v1/users/**").hasAnyRole("USER", "ADMIN")
				.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

				.anyRequest().authenticated()
			)
			// TODO: uncomment this when we create OAuth2ClientCOnfig...
//			.oauth2Login(oauth2 -> oauth2
//				.authorizationEndpoint(authorization -> authorization
//					.baseUri("/api/v1/auth/oauth2/authorization")
//				)
//				.defaultSuccessUrl("/api/v1/auth/oauth-login", true)
//				.failureUrl("/api/v1/auth/oauth-login?error=true")
//			)
			.authenticationProvider(authenticationProvider)
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOrigins(List.of(
			"http://localhost:3000",
			"http://localhost:5173"
		));

		configuration.setAllowedMethods(List.of(
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"OPTIONS"
		));

		configuration.setAllowedHeaders(List.of(
			"Authorization",
			"Content-Type",
			"X-Requested-With",
			"X-Forwarded-For",
			"X-Forwarded-Proto",
			"X-Forwarded-Host",
			"X-Forwarded-Port",
			"X-Forwarded-Prefix"
		));

		configuration.setExposedHeaders(List.of("Authorization"));

		configuration.setAllowCredentials(true);

		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
