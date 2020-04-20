package com.pamesh.security.service.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.pamesh.security.model.RoleModel;
import com.pamesh.security.model.UserModel;
import com.pamesh.security.repository.RoleRepository;
import com.pamesh.security.repository.UserRepository;
import com.pamesh.security.service.UserService;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Override
    public UserModel fetchUser(String userId) {
        return userRepository.findByUserId(userId);
    }

    @Override
    @Transactional
    public void saveUser() {
        //Save Roles
        RoleModel adminRole = RoleModel.builder().name("admin").build();
        RoleModel userRole = RoleModel.builder().name("user").build();
        
        Set<RoleModel> roles = new HashSet<>();
        roles.add(adminRole);
        roles.add(userRole);
        
        roleRepository.saveAll(roles);
        
        //Get Role with admin user
        RoleModel admin = roleRepository.findByRoleName("admin");
        
        UserModel user = UserModel.builder()
                .firstName("admin").lastName("user")
                .password(passwordEncoder.encode("password"))
                .userId("admin")
                .roles(Collections.singleton(admin))
                .build();
        
        
        userRepository.save(user);
        
    }

}
