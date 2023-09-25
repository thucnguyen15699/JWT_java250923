package com.example.java8jwt.Repository;


import com.example.java8jwt.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IUserRepo extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String name); //tim kiem trong db co user do khong
    Boolean existsByUsername(String username); // username xem ton tai trong db chua
    Boolean existsByEmail(String email); // email da ton tai trong db chua
}
