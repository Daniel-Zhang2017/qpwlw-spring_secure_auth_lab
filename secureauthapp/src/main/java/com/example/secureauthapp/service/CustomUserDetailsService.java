package com.example.secureauthapp.service;

import com.example.secureauthapp.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final Map<String, User> users = new HashMap<>();
    private final PasswordEncoder passwordEncoder;

    // Email validation pattern
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    // Use constructor injection without @Autowired (implicit in Spring 4.3+)
    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        
        // Optionally add some default users for testing
        // addDefaultUsers();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return user;
    }

    public void registerUser(String username, String password, String role, 
                           String firstName, String lastName, String email) {
        
        // Validation
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("Username already exists");
        }
        
        if (firstName == null || firstName.trim().isEmpty()) {
            throw new IllegalArgumentException("First name is required");
        }
        
        if (lastName == null || lastName.trim().isEmpty()) {
            throw new IllegalArgumentException("Last name is required");
        }
        
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }
        
        if (!isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid email format");
        }
        
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }

        String encodedPassword = passwordEncoder.encode(password);
        User user = new User(username, encodedPassword, role, firstName.trim(), lastName.trim(), email.trim());
        users.put(username, user);
    }

    private boolean isValidEmail(String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }

    // Helper method to get user by username
    public User getUserByUsername(String username) {
        return users.get(username);
    }

    // Optional: Method to add default users for testing
    private void addDefaultUsers() {
        String adminPassword = passwordEncoder.encode("admin123");
        User adminUser = new User("admin", adminPassword, "ROLE_ADMIN", "John", "Doe", "admin@example.com");
        users.put("admin", adminUser);

        String staffPassword = passwordEncoder.encode("staff123");
        User staffUser = new User("staff", staffPassword, "ROLE_STAFF", "Jane", "Smith", "staff@example.com");
        users.put("staff", staffUser);
    }
}