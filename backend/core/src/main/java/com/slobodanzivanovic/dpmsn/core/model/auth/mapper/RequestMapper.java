package com.slobodanzivanovic.dpmsn.core.model.auth.mapper;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.core.model.common.mapper.BaseMapper;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Mapper(componentModel = "spring")
public abstract class RequestMapper implements BaseMapper<RegisterRequest, UserEntity> {

	@Autowired
	protected BCryptPasswordEncoder passwordEncoder;

	@Mapping(source = "password", target = "password", qualifiedByName = "encodePassword")
	@Mapping(target = "id", ignore = true)
	@Mapping(target = "createdAt", ignore = true)
	@Mapping(target = "updatedAt", ignore = true)
	@Mapping(target = "createdBy", ignore = true)
	@Mapping(target = "updatedBy", ignore = true)
	@Mapping(target = "version", ignore = true)
	@Mapping(target = "enabled", constant = "false")
	@Mapping(target = "firstName")
	@Mapping(target = "lastName")
	@Mapping(target = "phoneNumber", ignore = true)
	@Mapping(target = "birthDate", ignore = true)
	@Mapping(target = "verificationCode", ignore = true)
	@Mapping(target = "verificationCodeExpiresAt", ignore = true)
	@Mapping(target = "roles", ignore = true)
	public abstract UserEntity map(RegisterRequest source);

	@Named("encodePassword")
	protected String encodePassword(String password) {
		return passwordEncoder.encode(password);
	}
	
}
