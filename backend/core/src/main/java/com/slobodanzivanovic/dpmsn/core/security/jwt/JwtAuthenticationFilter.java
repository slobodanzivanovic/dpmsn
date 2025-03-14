package com.slobodanzivanovic.dpmsn.core.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter for JWT-based authentication.
 * <p>
 * This filter intercepts incoming requests to validate any JWT tokens provided in the
 * Authorization header. If a valid token is found, it sets up the security context with
 * the authenticated user.
 * </p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final TokenBlacklistService tokenBlacklistService;

	/**
	 * Processes each request to extract and validate JWT tokens.
	 * <p>
	 * Checks for a JWT token in the Authorization header, validates it, and sets up
	 * the security context if valid.
	 * </p>
	 *
	 * @param request     The HTTP request
	 * @param response    The HTTP response
	 * @param filterChain The filter chain for further processing
	 * @throws ServletException If a servlet error occurs
	 * @throws IOException      If an I/O error occurs
	 */
	@Override
	protected void doFilterInternal(
		@NonNull HttpServletRequest request,
		@NonNull HttpServletResponse response,
		@NonNull FilterChain filterChain
	) throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String jwt = authHeader.substring(7);

		if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
			log.warn("Attempt to use blacklisted token: {}", jwt);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been invalidated");
			return;
		}

		try {
			String username = jwtService.extractUsername(jwt);

			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);

				if (jwtService.isTokenValid(jwt, userDetails)) {
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails,
						null, // null since we don't need password for token auth
						userDetails.getAuthorities());

					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					log.debug("Successfully authenticated user: {}", username);
				}
			}

		} catch (ExpiredJwtException e) {
			log.error("Expired JWT token: {}", e.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
			return;
		} catch (SignatureException e) {
			log.error("Invalid JWT signature: {}", e.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token signature");
			return;
		} catch (Exception e) {
			log.error("Error processing JWT token: {}", e.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error processing token");
			return;
		}

		filterChain.doFilter(request, response);
	}

}
