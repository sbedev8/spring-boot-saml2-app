package com.sbe.saml.samlapp.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping
@RestController
public class HomeController {

//    @GetMapping("/home")
//    public String home() {
//        return "hello World";
//    }

    @GetMapping("/home")
    public Saml2AuthenticatedPrincipal home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        return principal;
    }

}
