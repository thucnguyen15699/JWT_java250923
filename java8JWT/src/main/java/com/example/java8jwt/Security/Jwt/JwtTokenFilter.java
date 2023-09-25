package com.example.java8jwt.Security.Jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenFilter extends OncePerRequestFilter { // tim token trong request
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);
 @Autowired
 private JwtProvider jwtProvider;
 @Autowired
 private UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            String token = getJwt(request); // lay token
            if (token != null && jwtProvider.validateToken(token)) // kiem tra token co dung khong qua jwtProvider
            {
                String username = jwtProvider.getUserNameFromToken(token); // lay name tu token
                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // load name
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null,userDetails.getAuthorities());
                authenticationToken.setDetails( new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e){
            logger.error("can't set user authentication -> Message:{}",e);

        }
        filterChain.doFilter(request,response);
    }
    private String getJwt(HttpServletRequest request)
    {
        String authHeader = request.getHeader("Authorization");
        if (authHeader!= null && authHeader.startsWith("Bearer")){
            return authHeader.replace("Bearer", "");
        }
        return null;
    }
}
