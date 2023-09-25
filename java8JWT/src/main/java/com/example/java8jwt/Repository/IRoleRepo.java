package com.example.java8jwt.Repository;


import com.example.java8jwt.Model.Role;
import com.example.java8jwt.Model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IRoleRepo extends JpaRepository<Role,Long> {
    Optional<Role> findByName(RoleName name);
}
