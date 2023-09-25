package com.example.java8jwt.Service;

import com.example.java8jwt.Model.Role;
import com.example.java8jwt.Model.RoleName;

import java.util.Optional;

public interface IRoleServ {
    Optional<Role> findByName(RoleName name);
}
