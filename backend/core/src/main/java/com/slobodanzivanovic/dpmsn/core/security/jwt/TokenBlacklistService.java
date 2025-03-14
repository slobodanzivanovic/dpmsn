package com.slobodanzivanovic.dpmsn.core.security.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing blacklisted JWT tokens.
 * <p>
 * This service maintains a list of invalidated tokens to prevent their reuse.
 * In a production environment, this should be backed by a distributed cache like Redis
 * to ensure blacklist consistency across multiple application instances.
 * </p>
 */
@Service
@Slf4j
public class TokenBlacklistService {

	// we also can use HashSet here instead of conhashmap but let's stick with this for thread safety
	// in future we will use redis for this shiat
	private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

	/**
	 * Adds a token to the blacklist.
	 * <p>
	 * Once a token is blacklisted, it will no longer be accepted for authentication.
	 * </p>
	 *
	 * @param token The JWT token to blacklist
	 */
	public void blacklistToken(String token) {
		blacklistedTokens.add(token);
		log.debug("Token blacklisted: {}, Total blacklisted tokens: {}", token, blacklistedTokens.size());
	}

	/**
	 * Checks if a token is blacklisted.
	 *
	 * @param token The JWT token to check
	 * @return true if the token is blacklisted, false otherwise
	 */
	public boolean isTokenBlacklisted(String token) {
		return blacklistedTokens.contains(token);
	}

	/**
	 * TODO:
	 *  clears expired tokens from the blacklist to prevent memory leaks
	 *  in prod consider using a scheduled task
	 *  ...check expiration and remove accordingly
	 */
	public void clearExpiredTokens() {
		log.info("Token blacklist cleanup would happen here in a prod environment");
	}

}
