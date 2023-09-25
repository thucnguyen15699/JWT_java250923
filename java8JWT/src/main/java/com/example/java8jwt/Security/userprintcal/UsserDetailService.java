package com.example.java8jwt.Security.userprintcal;


import com.example.java8jwt.Model.User;
import com.example.java8jwt.Repository.IUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class UsserDetailService implements UserDetailsService {
    @Autowired
    private IUserRepo userRepo;
//    private Object User;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException { // tim username co ton tai trne db k
        User user = userRepo.findByUsername(userName).orElseThrow(()-> new UsernameNotFoundException("user not found -> username or password"+userName));
        return UserPrintciple.build(user); //UserPrincipal  được trả về, đại diện cho thông tin của người dùng và quyền truy cập của họ.
    }
}
