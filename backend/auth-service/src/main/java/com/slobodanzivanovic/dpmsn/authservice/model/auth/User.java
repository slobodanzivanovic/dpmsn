package com.slobodanzivanovic.dpmsn.authservice.model.auth;

/**
 * Represents a user named {@link User} in the system
 * This record contains information about the user's identity, contact details, status, and type
 */
public record User(

	String id,

	String email,

	String firstName,

	String lastName,

	String phoneNumber,

	String userStatus,

	String userType
) {
}
