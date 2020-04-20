package com.pamesh;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import com.pamesh.security.service.UserService;

/**
 * The Class SpringSecurityJwtApplication.
 *
 * @author Pamesh Bansal
 */
@SpringBootApplication
@EnableAutoConfiguration(exclude = {ErrorMvcAutoConfiguration.class})
public class SpringSecurityJwtApplication implements CommandLineRunner {

     @Autowired
     UserService userService;
    
    /**
     * The main method.
     *
     * @param args the arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        
        userService.saveUser();

    }

}
