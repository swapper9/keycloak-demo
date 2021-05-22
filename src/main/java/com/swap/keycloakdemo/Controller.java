package com.swap.keycloakdemo;

import lombok.extern.log4j.Log4j2;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@Log4j2
public class Controller {

    @GetMapping(value = "/user/key")
    public String getUserKey(@RequestParam(value = "id") long id) {
        KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
            .getAuthentication();
        final Principal principal = (Principal) authentication.getPrincipal();

        if (principal instanceof KeycloakPrincipal) {
            KeycloakPrincipal<KeycloakSecurityContext> kPrincipal = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
            AccessToken accessToken = kPrincipal.getKeycloakSecurityContext().getToken();

            if ("login-app".equals(accessToken.getIssuedFor())) {
                return "Request granted for id: " + id;
            }
        }
        return "Bad principal";
    }

    @GetMapping(value = "/restricted/key")
    public String getRestrictedKey(@RequestParam(value = "id") long id) {
        return "Request granted for id: " + id;
    }


}
