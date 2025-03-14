package com.slobodanzivanovic.dpmsn.core.security.jwt;

import com.slobodanzivanovic.dpmsn.core.model.auth.entity.RoleEntity;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Custom implementation of Spring Security's UserDetails interface.
 * <p>
 * This record wraps a UserEntity and adapts it to the UserDetails interface
 * required by Spring Security for authentication and authorization. It provides
 * methods to access user information and determine account status.
 * </p>
 *
 * @param user The UserEntity to be wrapped
 */
public record CustomUserDetails(UserEntity user) implements UserDetails {

	/**
	 * Returns the authorities granted to the user.
	 * <p>
	 * Converts the user's role entities into Spring Security GrantedAuthority objects.
	 * </p>
	 *
	 * @return A collection of GrantedAuthority objects
	 */
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.getRoles().stream()
			.map(RoleEntity::getName)
			.map(SimpleGrantedAuthority::new)
			.collect(Collectors.toList());
	}

	/**
	 * Returns the password used to authenticate the user.
	 *
	 * @return The user's password
	 */
	@Override
	public String getPassword() {
		return user.getPassword();
	}

	/**
	 * Returns the username used to authenticate the user.
	 *
	 * @return The user's username
	 */
	@Override
	public String getUsername() {
		return user.getUsername();
	}

	/**
	 * Indicates whether the user's account has expired.
	 *
	 * @return true if the user's account is valid (non-expired), false otherwise
	 */
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	/**
	 * Indicates whether the user is locked or unlocked.
	 *
	 * @return true if the user is not locked, false otherwise
	 */
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	/**
	 * Indicates whether the user's credentials (password) has expired.
	 *
	 * @return true if the user's credentials are valid (non-expired), false otherwise
	 */
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	/**
	 * Indicates whether the user is enabled or disabled.
	 *
	 * @return true if the user is enabled, false otherwise
	 */
	@Override
	public boolean isEnabled() {
		return user.isEnabled();
	}

}
