package com.slobodanzivanovic.dpmsn.userservice.model.user.entity;

import com.slobodanzivanovic.dpmsn.userservice.model.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * Represents an entity named {@link InvalidTokenEntity} for storing invalid tokens in the system
 * This entity tracks tokens that have been invalidated to prevent their reuse
 */
@Entity
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Table(name = "invalid_token")
public class InvalidTokenEntity extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	private String id;

	private String tokenId;

}
