# JWT_java250923
Dự án sử dụng Jwt Authentication với Spring Boot 2.1.7
# Tạo file
Tạo project bằng cách sử dụng **Spring Initializr**,**Spring Assistant**,hoặc truy cập https://start.spring.io/
 
**Chú ý:** đây là project sử dụng java 8, và không dùng maven mà dùng gradle
+ Name: JWTjava
 + Language: Java
 +  Type: maven
  + Group: com.example
  + Artifact: JWTjava
  + Package name: com.example.jwtexample
  + Packaging: Jar

# Thêm các dependency cho file build.gradle
+ dependencies
>dependencies {
implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
implementation 'org.springframework.boot:spring-boot-starter-thymeleaf'
implementation 'org.springframework.boot:spring-boot-starter-web'
developmentOnly 'org.springframework.boot:spring-boot-devtools'
implementation 'mysql:mysql-connector-java:8.0.23'
runtimeOnly 'mysql:mysql-connector-java'
testImplementation 'org.springframework.boot:spring-boot-starter-test'
implementation group: 'javax.validation', name: 'validation-api', version: '2.0.1.Final'
implementation group: 'org.hibernate', name: 'hibernate-validator', version: '6.0.10.Final'

+ Security
>implementation group: 'org.springframework.security', name: 'spring-security-web', version: '5.4.2'
    implementation group: 'org.springframework.security', name: 'spring-security-config', version: '5.4.2'
    implementation group: 'org.springframework.security', name: 'spring-security-taglibs', version: '5.4.2'
    implementation group: 'org.springframework.security', name: 'spring-security-core', version: '5.4.3'
    implementation group: 'io.jsonwebtoken', name: 'jjwt', version: '0.9.0'
}
# Kết nối đến database MYSQL Server
Trong file `application.properties` chứa thông tin kết nối đến DB 
+ `spring.datasource.url`: Tên DB
+ `spring.datasource.username`: Tên đăng nhập vào DB
+ `spring.datasource.password`: Password đăng nhập.
```c 
spring.datasource.url=jdbc:mysql://localhost:3306/loginJWT
spring.datasource.username=root
spring.datasource.password=15061999
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
management.security.enabled=false
spring.jpa.show-sql=true
```
# Đổi cổng thành 8080 
+ File sửa  `application.properties`
  server.port=8080
  # Tạo các package
+ Tại  `src/main/java/com/jwt/example/java8jwt` gồm các package `Model`,`Controller`,`Repository`,`Service`,...
# File Controller 
+ Chức năng xử lý thêm thông tin tài khoản và xử lý chức năng login 
```c package com.example.java8jwt.Controller;

import com.example.java8jwt.Model.Role;
import com.example.java8jwt.Model.RoleName;
import com.example.java8jwt.Model.User;
import com.example.java8jwt.Security.Jwt.JwtProvider;
import com.example.java8jwt.Security.userprintcal.UserPrintciple;
import com.example.java8jwt.Service.impl.RoleServicelmpl;
import com.example.java8jwt.Service.impl.UserServiceImpl;
import com.example.java8jwt.dto.reponse.JwtResponse;
import com.example.java8jwt.dto.reponse.ReponMessage;
import com.example.java8jwt.dto.request.SignInForm;
import com.example.java8jwt.dto.request.SignUpFrom;
import org.springframework.beans.factory.annotation.Autowired;
//import com.example.demo.security.userprincal.UserPrinciple;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@RequestMapping("/api/auth")
@RestController
public class AuthController {
    @Autowired
    UserServiceImpl userService;
    @Autowired
    RoleServicelmpl roleServicelmpl;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtProvider jwtProvider;
    @PostMapping("/signup")
    public ResponseEntity<?> register(@Valid @RequestBody SignUpFrom signUpFrom)
    {
        if (userService.existsByUsername(signUpFrom.getUsername())){
            return new ResponseEntity<>(new ReponMessage("the username existed! Please try again! "), HttpStatus.OK);
        }
        if (userService.existsByEmail(signUpFrom.getEmail()))
        {
            return new ResponseEntity<>(new ReponMessage("the email existed! Please try again!"),HttpStatus.OK);
        }
        User user = new User(signUpFrom.getName(),signUpFrom.getUsername(),signUpFrom.getEmail(),passwordEncoder.encode(signUpFrom.getPassword()));
        Set<String> strRoles = signUpFrom.getRoles();
        Set<Role> roles = new HashSet<>();
        strRoles.forEach(role ->{
            switch (role){
                case "admin":
                    Role adminRole = roleServicelmpl.findByName(RoleName.ADMIN).orElseThrow(
                            ()-> new RuntimeException("role not found")
                    );
                    roles.add(adminRole);
                    break;
                    case "pm":
                        Role pmRole = roleServicelmpl.findByName(RoleName.PM).orElseThrow(
                                ()-> new RuntimeException("role not found")
                        );
                        roles.add(pmRole);
                        break;
                default:
                    Role userRole = roleServicelmpl.findByName(RoleName.USER).orElseThrow(
                            ()-> new RuntimeException("role not found")
                    );
                    roles.add(userRole);
            }
        });
        user.setRoles(roles);
        userService.save(user);
        System.out.println(signUpFrom.getUsername());
        return new ResponseEntity<>(new ReponMessage("Create user sucsses!"),HttpStatus.OK);
    }
    @PostMapping("/sigin")
    public ResponseEntity <?> login(@Valid @RequestBody SignInForm signInForm)
    {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signInForm.getUsername(), signInForm.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.creatToken(authentication);
        UserPrintciple userPrintciple = (UserPrintciple) authentication.getPrincipal();
        return  ResponseEntity.ok(new JwtResponse(token,userPrintciple.getName(),userPrintciple.getAuthorities()));
    }
}
 ```
# Model `User`,`Role`
+ phần `RoleName` để lấy các quyền
File `User`
```c 
package com.example.java8jwt.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users",uniqueConstraints = {
        @UniqueConstraint(columnNames = {
                "username"
        }), // khong tao trung lap
        @UniqueConstraint(columnNames = {
                "email"
        }) // khong tao trung lap du lieu o hai cot nay
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column
    @NotBlank // khong dc trong
    @Size(min = 3, max = 50)
    private String name;

    @NotBlank // khong dc trong
    @Size(min = 3, max = 51)
    @Column(name = "username")
    private String username;
    @Column
    @NaturalId //id tu nhien
    @NotBlank // khong dc trong
    @Size( max = 51)
    @Email
    private String email;
    @JsonIgnore // khong truyenf pass ra ngoai(k lo pass)
    @NotBlank
    @Size(min = 6,max = 60)
    private String password;
    @Lob // danh dau ky tu rat dai
    private String avatar;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "userrole", joinColumns = @JoinColumn(name = "user_id"),inverseJoinColumns = @JoinColumn(name = "role_id")) // tao ra bnag phu de jon
    Set<Role> roles = new HashSet<>();


    public User() {

    }

    public User(Long id, String name, String username, String email, String password, String avatar, Set<Role> roles) {
        this.id = id;
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
        this.avatar = avatar;
        this.roles = roles;
    }
    public User(@NotBlank @Size(min = 3, max = 50)String name,
                @NotBlank @Size(min = 3, max = 50)String username,
                @NotBlank @Size(max = 50) @Email String email,
                @NotBlank @Size(min = 6, max = 100)String encode) {
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = encode;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
```
Fiel `Role`
```c
package com.example.java8jwt.Model;

import org.hibernate.annotations.NaturalId;

import javax.persistence.*;

@Entity
@Table(name = "role")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Enumerated(EnumType.STRING) // kieu du lieu
    @NaturalId //id tu nhien
    @Column(length = 60) // do dai 60
    private RoleName name;

    public Role() {
    }

    public Role(Long id, RoleName name) {
        this.id = id;
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public RoleName getName() {
        return name;
    }

    public void setName(RoleName name) {
        this.name = name;
    }
}
 
```
# Tạo các Service
Các file trong Service sẽ thực hiện các công việc như định nghĩa các phương thức dành cho việc quản lý người dùng trong ứng dụng gồm các file `IUserSevice`,`IRoleServ`
File `UserServ`, chức năng định nghĩa các phương thức quản lý người dùng
```c 
package com.example.java8jwt.Service;



import com.example.java8jwt.Model.User;

import java.util.Optional;

public interface IUserSevice {
    Optional<User> findByUserName(String name); //tim kiem trong db co user do khong
    Boolean existsByUsername(String username); // username xem ton tai trong db chua
    Boolean existsByEmail(String email); // email da ton tai trong db chua
    User save(User user);
}

```
File `RoleServ`, quản lý người dùng ứng dụng và trả về 1 đối tượng
```c 
package com.example.java8jwt.Service;

import com.example.java8jwt.Model.Role;
import com.example.java8jwt.Model.RoleName;

import java.util.Optional;

public interface IRoleServ {
    Optional<Role> findByName(RoleName name);
}

```
# Tạo Security 
Security nơi chứa các chức năng tạo JWT token 
File `JwtEntryPonit`: Lớp này xử lý việc bắt các exception liên quan đến xác thực JWT không thành công. Nó implements AuthenticationEntryPoint và ghi đè phương thức commence. Khi có exception liên quan đến xác thực JWT, phương thức commence sẽ được gọi và trả về một HTTP Response với mã lỗi 401 Unauthorized
```c 
package com.example.java8jwt.Security.Jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtEntryPonit implements AuthenticationEntryPoint  {
    private static final Logger logger = LoggerFactory.getLogger(JwtEntryPonit.class);
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error Message {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_ACCEPTED, "Error -> Unauthorized");
    }
}

```
File `JwtProvider`,Lớp này chứa các phương thức để tạo và xác minh JWT token
```c 
package com.example.java8jwt.Security.Jwt;


import com.example.java8jwt.Security.userprintcal.UserPrintciple;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;
//import java.util.logging.Logger;

@Component
public class JwtProvider { // tạo JWT token
    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
//    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);
    private String jwtSecret = "thuc15";
    private int jwtExporation = 86400;
    public  String creatToken(Authentication authentication)
    {
        UserPrintciple userPrinciple = (UserPrintciple) authentication.getPrincipal();
        return Jwts.builder().setSubject(userPrinciple.getUsername()) // Jwts.builder() để xây dựng và tạo JWT, "subject" được đặt chứa thông tin về người dùng hoặc thực thể cụ thể nào đó.
                .setIssuedAt(new Date())// Đặt thời điểm phát hành của JWT bằng thời gian hiện tại.
                .setExpiration(new Date(new Date().getTime()+jwtExporation*1000)) // set time jwt het han
                .signWith(SignatureAlgorithm.HS512, jwtSecret) // tieu chuan ma hoa hs512 theo key da dat trc
                .compact();
    }
    public boolean validateToken(String token) // check token 
    {
        try
        {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token); // xac thuc chu ky co dung k
            return true;
        }catch(SignatureException  e){
            logger.error("Invalid jwt signture-> message: {}",e);
//            return false;
        }catch(MalformedJwtException e){
            logger.error("Invalid format token-> message: {}",e); // k dung format
//            return false;
        }catch(ExpiredJwtException  e){ // het thoi gian
            logger.error("Expired token-> message: {}",e);
//            return false;
        }catch(UnsupportedJwtException e){ // khong ho tro
            logger.error("Unsupport jwt token-> message: {}",e);
//            return false;
        }catch(IllegalArgumentException e){ // chua ky tu trong khong hop le
            logger.error("Jwt claims string is empty token-> message: {}",e);
//            return false;
        }
        return false;
    }

    public String getUserNameFromToken(String token)
    {
        String userName = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token).getBody().getSubject(); // lay ra userName trong token
        return userName;
    }
}

```
File `Jwttoken`,Lớp này dùng để lọc các request đến server và kiểm tra xem chúng có chứa JWT token hợp lệ hay không.
File `UserPrincipal`,Lớp này implements UserDetails, một interface của Spring Security sử dụng để giữ thông tin của người dùng đã xác thực.
File `UserDetailsServiceImpl`,Lớp này implements UserDetailsService, một interface của Spring Security cho phép tùy chỉnh cách lấy thông tin người dùng từ cơ sở dữ liệu
# Tạo file Config
Chức năng cho phép bạn tùy chỉnh cấu hình bảo mật của ứng dụng sử dụng `WebSecurityConfigurerAdapter`,`WebSecurityConfigurerAdapter` hiện tại 
rất ít được hỗ trợ ở java phiên bản spring boot cao.
```c 
package com.example.java8jwt.config;

import com.example.java8jwt.Security.Jwt.JwtEntryPonit;
import com.example.java8jwt.Security.Jwt.JwtTokenFilter;
import com.example.java8jwt.Security.userprintcal.UsserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UsserDetailService usserDetailService;
    @Autowired
    private JwtEntryPonit jwtEntryPonit;

    @Bean
    public JwtTokenFilter jwtTokenFilter(){
        return new JwtTokenFilter();
    }
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception{
        authenticationManagerBuilder.userDetailsService(usserDetailService).passwordEncoder(passwordEncoder());
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.cors().and().csrf().disable().
                authorizeRequests().antMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
                .and().exceptionHandling()
                .authenticationEntryPoint(jwtEntryPonit)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

    }
}

```
# Packega Dto
Trong packega này chứa các file nhằm mục đích hạn chế bớt dữ liệu thừa khi lấy dữ liệu ra
như file `SignInFrom`, file chứa các thông tin nhận vào khi đăng nhập, hạn chế các trường thông tin thừa.
```c 
package com.example.java8jwt.dto.request;

public class SignInForm {
    private String username;
    private String password;

    public SignInForm() {
    }

    public SignInForm(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

```

# Test chức năng trên PostMan 
Đầu tiên chúng ta cần tạo tài khoản và cấp quyền cho tài khoản
+ Chọn phương thức `Post` trên post man
+ Với đường dẫn được để `http://localhost:8080/api/auth/signup`
+ Chọn `Body`, và chọn `raw`, chọn kiểu dữ liệu `JSON` nhập các thông tin cần thiêt sau
```c 
        "name":"human",
        "username":"admin",
        "email":"admin@gmail.com",
        "password":"admin",
        "roles":["admin"] // quyền 
```
Sau khi tạo thành công sẽ báo `"message": "Create user sucsses!"`, sau đó ta check trong DB sẽ có các dữ liệu như sau:
![example](nguoidung.png)
# Test chức năng đăng nhập sau khi đã tạo account
+ Chọn phương thức `Post` trên post man
+ Với đường dẫn được để `http://localhost:8080/api/auth/sigin`
+ Chọn `Body`, và chọn `raw`, chọn kiểu dữ liệu `JSON` nhập các thông tin cần thiêt sau
```c 
        "username":"admin",
        "password":"admin"
```
Sau khi đăng nhập ta lấy được các thông tin của người dùng và sử dụng khi đẩy dữ liệu lên `VIEW`
```c 
{
    "id": null,
    "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbkBnbWFpbC5jb20iLCJpYXQiOjE2OTU2OTg2MjUsImV4cCI6MTY5NTc4NTAyNX0.lc-PRnN_4gadFqOxhG9eDQZmLtOFLWhSjgF9ka0TzFqlRXh22Cz7JYxlbUR6kAFUcYrlJS507Fr91a9MS2pFKg",
    "type": "Bearer",
    "name": "human", // ten người dùng
    "roles": [
        {
            "authority": "ADMIN" // quyền khi đẩy lên view
        }
    ]
}
```