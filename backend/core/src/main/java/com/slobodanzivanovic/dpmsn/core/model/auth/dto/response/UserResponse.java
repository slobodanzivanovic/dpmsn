package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

import java.util.Set;
import java.util.UUID;

public record UserResponse(

	UUID id,

	String username,

	String email,

	String firstName,

	String lastName,

	boolean enabled,

	Set<String> roles

) {
}
