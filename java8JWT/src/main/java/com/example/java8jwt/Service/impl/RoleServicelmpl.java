package com.example.java8jwt.Service.impl;

import com.example.java8jwt.Model.Role;
import com.example.java8jwt.Model.RoleName;
import com.example.java8jwt.Repository.IRoleRepo;

import com.example.java8jwt.Service.IRoleServ;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServicelmpl implements IRoleServ {
    @Autowired
    IRoleRepo roleRepo;
    @Override
    public Optional<Role> findByName(RoleName name) {
        return roleRepo.findByName(name);
//        return Optional.empty();
    }
}
