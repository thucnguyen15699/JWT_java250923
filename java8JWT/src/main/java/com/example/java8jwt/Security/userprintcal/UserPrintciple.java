package com.example.java8jwt.Security.userprintcal;


import com.example.java8jwt.Model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserPrintciple implements UserDetails {
    private Long id;
    private String name;
    private String email;
    private String username;
    @JsonIgnore
    private String password;
    private  String avatar;
    private Collection<? extends GrantedAuthority> roles;


    public UserPrintciple() {
    }


    public UserPrintciple(Long id, String name, String email, String username, String password, String avatar, Collection<? extends GrantedAuthority> roles) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.username = username;
        this.password = password;
        this.avatar = avatar;
        this.roles = roles;
    }
    public static UserPrintciple build(User user){
        List<GrantedAuthority> authorities = user.getRoles().stream().map(role ->
            new SimpleGrantedAuthority(role.getName().name())).collect(Collectors.toList()); // chuyen set thanh lisst
        return new UserPrintciple(
                user.getId(),
                user.getName(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                user.getAvatar(),
                authorities
        );
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // Phương thức này trả về danh sách các quyền
        return roles;
    }

    @Override
    public String getPassword() { // Phương thức này trả về mật khẩu đã được mã hóa của người dùng
        return password;
    }

    @Override
    public String getUsername() { //Phương thức này trả về tên người dùng (username) của người dùng
        return username;
    }

    @Override
    public boolean isAccountNonExpired() { //  Phương thức này kiểm tra xem tài khoản của người dùng có hết hạn hay không
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // Phương thức này kiểm tra xem tài khoản của người dùng có bị khóa hay không
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // Phương thức này kiểm tra xem thông tin xác thực của người dùng (ví dụ: mật khẩu) có hết hạn hay không
        return true;
    }

    @Override
    public boolean isEnabled() { //  Phương thức này kiểm tra xem tài khoản của người dùng có được kích hoạt (enabled) hay không.
        return true;
    }
}
