package com.slobodanzivanovic.dpmsn.authservice.filter;

import java.io.IOException;

import org.apache.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.slobodanzivanovic.dpmsn.authservice.client.UserServiceClient;
import com.slobodanzivanovic.dpmsn.authservice.model.auth.Token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Filter named {@link CustomBearerTokenAuthenticationFilter} for authenticating requests using a Bearer token
 * This filter validates the Bearer token by calling the user service
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomBearerTokenAuthenticationFilter extends OncePerRequestFilter {

	private final UserServiceClient userServiceClient;

	/**
	 * Filters requests to authenticate using a Bearer token
	 *
	 * @param httpServletRequest  the HTTP request
	 * @param httpServletResponse the HTTP response
	 * @param filterChain         the filter chain
	 * @throws ServletException if an error occurs during filtering
	 * @throws IOException      if an I/O error occurs during filtering
	 */
	@Override
	protected void doFilterInternal(@SuppressWarnings("null") @NonNull final HttpServletRequest httpServletRequest,
									@SuppressWarnings("null") @NonNull final HttpServletResponse httpServletResponse,
									@SuppressWarnings("null") @NonNull final FilterChain filterChain) throws ServletException, IOException {

		log.debug("API Request was secured with Security!");

		final String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

		if (Token.isBearerToken(authorizationHeader)) {
			final String jwt = Token.getJwt(authorizationHeader);
			userServiceClient.validateToken(jwt);
		}

		filterChain.doFilter(httpServletRequest, httpServletResponse);

	}

}
