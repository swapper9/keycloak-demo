package com.swap.keycloakdemo;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@Log4j2
public class Controller {

    @GetMapping(value = "/any")
    public ResponseEntity<String> getAny() {
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping(value = "/user")
    public ResponseEntity<Integer> getUserKey() {
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping(value = "/admin")
    public String getRestrictedKey() {
        return "Full access granted";
    }

//    @SuppressWarnings("unchecked")
//    private int getAuthId() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        int authId = 0;
//        final Principal principal = (Principal) authentication.getPrincipal();
//        authentication.getDetails()
//            KeycloakPrincipal<KeycloakSecurityContext> kPrincipal = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
//            AccessToken accessToken = principal.getKeycloakSecurityContext().getToken();
//            authId = (Integer) accessToken.getOtherClaims().get("authId");
//        return authId;
//    }
}
