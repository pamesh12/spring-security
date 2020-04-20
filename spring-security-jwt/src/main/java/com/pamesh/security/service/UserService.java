package com.pamesh.security.service;

import com.pamesh.security.model.UserModel;

public interface UserService {

    UserModel fetchUser(String userId);
    
    void saveUser();
}
