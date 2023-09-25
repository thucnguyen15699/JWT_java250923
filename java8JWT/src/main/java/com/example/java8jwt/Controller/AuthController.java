package com.example.java8jwt.Controller;

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
