package com.slobodanzivanovic.dpmsn.core.repository.auth;

import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, UUID> {

	Optional<UserEntity> findByEmail(String email);

	Optional<UserEntity> findByUsername(String username);

}
