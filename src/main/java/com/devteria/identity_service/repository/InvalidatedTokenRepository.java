package com.devteria.identity_service.repository;

import com.devteria.identity_service.entity.InvalidatedToken;
import com.devteria.identity_service.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, String> {

}