package com.example.java8jwt.Service;



import com.example.java8jwt.Model.User;

import java.util.Optional;

public interface IUserSevice {
    Optional<User> findByUserName(String name); //tim kiem trong db co user do khong
    Boolean existsByUsername(String username); // username xem ton tai trong db chua
    Boolean existsByEmail(String email); // email da ton tai trong db chua
    User save(User user);
}
