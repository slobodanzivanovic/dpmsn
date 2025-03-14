package com.slobodanzivanovic.dpmsn.core.model.auth.mapper;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.UserResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.core.model.common.mapper.BaseMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserMapper extends BaseMapper<UserEntity, UserResponse> {

	@Mapping(source = "roles", target = "roles", qualifiedByName = "rolesToStrings")
	@Override
	UserResponse map(UserEntity source);

	@Named("rolesToStrings")
	default Set<String> rolesToStrings(Set<com.slobodanzivanovic.dpmsn.core.model.auth.entity.RoleEntity> roles) {
		if (roles == null) {
			return Set.of();
		}
		return roles.stream()
			.map(role -> role.getName())
			.collect(Collectors.toSet());
	}
	
}
