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
public class JwtProvider {
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
    public boolean validateToken(String token)
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
