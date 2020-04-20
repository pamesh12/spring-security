package com.pamesh.security.auth;

import java.io.Serializable;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

/**
 * The Class ResourcePermissonEvaluator.
 *
 * @author Pamesh Bansal
 */
public class ResourcePermissonEvaluator implements PermissionEvaluator {

    /**
     * Checks for permission.
     *
     * @param authentication the authentication
     * @param targetDomainObject the target domain object
     * @param permission the permission
     * @return true, if successful
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
       if(authentication == null || permission ==null) {
           return false;
       }
       return authentication.getAuthorities().stream().anyMatch(e->e.getAuthority().equals(permission));
    }

    /**
     * Checks for permission.
     *
     * @param authentication the authentication
     * @param targetId the target id
     * @param targetType the target type
     * @param permission the permission
     * @return true, if successful
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        // TODO Auto-generated method stub
        return false;
    }

}
