package com.pamesh.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/hello")
    @PreAuthorize("hasPermission('object','admin')")
    public ResponseEntity<String> user() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return new ResponseEntity<>("Hello " + auth.getPrincipal(), HttpStatus.OK);
    }
}
