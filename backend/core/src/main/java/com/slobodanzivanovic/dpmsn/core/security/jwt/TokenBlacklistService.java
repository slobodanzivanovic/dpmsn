package com.slobodanzivanovic.dpmsn.core.security.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TODO:
 *  in a prod environment, this should be backed by redis or another distributed cache
 */
@Service
@Slf4j
public class TokenBlacklistService {

	// we also can use HashSet here instead of conhashmap but let's stick with this for thread safety
	// in future we will use redis for this shiat
	private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

	public void blacklistToken(String token) {
		blacklistedTokens.add(token);
		log.debug("Token blacklisted: {}, Total blacklisted tokens: {}", token, blacklistedTokens.size());
	}

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
