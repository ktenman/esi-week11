package com.esi.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		DatabaseInitializer.initialize("usercredentials_db");
		SpringApplication.run(AuthServiceApplication.class, args);
	}


}
