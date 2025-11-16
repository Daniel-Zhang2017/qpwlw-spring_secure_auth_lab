package com.example.secureauthapp.controller;

import com.example.secureauthapp.model.User;
import com.example.secureauthapp.service.CustomUserDetailsService;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
public class WebsiteController {

    private final CustomUserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;

    public WebsiteController(CustomUserDetailsService userDetailsService, 
                           AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/home")
    public String homepage(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return "redirect:/login";
        }

        String username = authentication.getName();
        model.addAttribute("username", username);

        // Get user details including first name
        User user = userDetailsService.getUserByUsername(username);
        if (user != null) {
            model.addAttribute("firstName", user.getFirstName());
        }

        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .findFirst()
            .orElse("ROLE_STAFF");

        if (role.equals("ROLE_ADMIN")) {
            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEEE, MMMM d, yyyy 'at' hh:mm a");
            String formattedDateTime = now.format(formatter);
            model.addAttribute("currentDateTime", formattedDateTime);
            return "admin";
        } else {
            return "viewer";
        }
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String role,
            @RequestParam String firstName,
            @RequestParam String lastName,
            @RequestParam String email
    ) {
        try {
            userDetailsService.registerUser(username, password, role, firstName, lastName, email);
        } catch (Exception e) {
            // URL encode the error message for safety
            String errorMessage = e.getMessage().replace(" ", "+");
            return "redirect:/register?error=" + errorMessage;
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            // If auto-login fails, just redirect to login page
            return "redirect:/login?success";
        }

        return "redirect:/login?success";
    }
}