package com.swap.keycloakdemo;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Log4j2
public class Controller {

    @GetMapping(value = "/any")
    public ResponseEntity<String> getAny() {
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping(value = "/user")
    public ResponseEntity<String> getUserKey(@AuthenticationPrincipal Jwt token) {
        StringBuilder builder = new StringBuilder();
        token.getClaims().forEach((k, v) -> builder.append(k).append(" :").append(v.toString()).append("\n"));
        return new ResponseEntity<>(builder.toString(), HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping(value = "/admin")
    public String getRestrictedKey() {
        return "Full access granted";
    }

}
