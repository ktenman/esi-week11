package com.esi.authservice.users.controller;

import com.esi.authservice.jwt.JwtService;
import com.esi.authservice.users.dto.UserDto;
import com.esi.authservice.users.model.User;
import com.esi.authservice.users.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@Slf4j
//@CrossOrigin(origins = "http://localhost:8080/") //@CrossOrigin("*")
@RestController
@RequestMapping("/api/auth")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    // a new end-point that allows users to authenticate themselves and generate the jwt token
    //This endpoint will receive the userDto, authenticate her/him with existing users in the database, then if authenticated, it will create the jwt
    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody UserDto userDto) {

        // authenticationManager.authenticate attempts to authenticate the passed Authentication object, returning a fully populated Authentication object (including granted authorities) if successful.
        // UsernamePasswordAuthenticationToken can be used by the authenticationManager and we are passing the user name and password to it.
        // To use the authenticationManager, you need to define a Bean for it, check SecurityConfig.java, it is defined there.
        // Note that verifying the user is a required before generating the token, otherwise, we will be generating tokens for users that we cannot authenticate

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDto.getName(), userDto.getPassword()));
        // If the user is authenticated we generate the token, otherwise, we throw an exception
        log.info("authentication.isAuthenticated()  {} ", authentication);

        if (authentication.isAuthenticated()) {
            log.info("jwtService.generateToken(authRequest.getName())  {} ", jwtService.generateToken(userDto.getName()).toString());
            return jwtService.generateToken(userDto.getName());
        } else {
            throw new UsernameNotFoundException("The user cannot be authenticated");
        }
    }


    // an end point for signing up new users
    @PostMapping("/signup")
    public User signupUser(@RequestBody User user) {
        return userService.addUser(user);
    }


    @GetMapping("/public")
    public String publicAPI() {
        return "This is an unprotected endpoint";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String adminAPI() {
        return "Protected endpoint - only admins are allowed";
    }

    @GetMapping("/user")
    public String userAPI() {
        return "Protected endpoint - only users are allowed";
    }
}
