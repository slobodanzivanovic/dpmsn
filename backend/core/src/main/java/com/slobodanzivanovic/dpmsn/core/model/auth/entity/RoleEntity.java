package com.slobodanzivanovic.dpmsn.core.model.auth.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.slobodanzivanovic.dpmsn.core.model.common.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true, exclude = "users")
public class RoleEntity extends BaseEntity {

	@Column(name = "name", nullable = false, unique = true)
	private String name;

	@Column(name = "status", nullable = false)
	@Builder.Default
	private boolean status = true;

	@ManyToMany(mappedBy = "roles")
	@JsonIgnore
	@Builder.Default
	private Set<UserEntity> users = new HashSet<>();

}
