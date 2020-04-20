package com.pamesh.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import com.pamesh.security.model.RoleModel;

@Repository
public interface RoleRepository extends JpaRepository<RoleModel, Long>{

    @Query("select r from RoleModel r where name = :name")
    RoleModel findByRoleName(String name);
    
}
