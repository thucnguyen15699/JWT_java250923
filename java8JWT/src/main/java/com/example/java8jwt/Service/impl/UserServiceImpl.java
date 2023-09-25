package com.example.java8jwt.Service.impl;


import com.example.java8jwt.Model.User;
import com.example.java8jwt.Repository.IUserRepo;
import com.example.java8jwt.Service.IUserSevice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
public class UserServiceImpl implements IUserSevice {
    @Autowired
    IUserRepo userRepo;
    @Override
    public Optional<User> findByUserName(String name) {
        return userRepo.findByUsername(name);
//        return Optional.empty();
    }

    @Override
    public Boolean existsByUsername(String username) {
        return userRepo.existsByUsername(username);
//        return null;
    }

    @Override
    public Boolean existsByEmail(String email) {
        return userRepo.existsByEmail(email);
//        return null;
    }

    @Override
    public User save(User user) {
        return userRepo.save(user);
//        return null;
    }
}
