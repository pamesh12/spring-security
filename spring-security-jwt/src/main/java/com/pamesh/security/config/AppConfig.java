package com.pamesh.security.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * The Class AppConfig.
 *
 * @author Pamesh Bansal
 */
@Configuration
@ComponentScan(basePackages = "com.pamesh")
@EnableWebMvc
public class AppConfig {

}
