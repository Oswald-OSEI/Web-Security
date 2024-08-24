package attendancemanagement.web_security_analysis.controller;

import attendancemanagement.web_security_analysis.model.*;
import attendancemanagement.web_security_analysis.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;
import attendancemanagement.web_security_analysis.service.UserService;
import java.util.Set;


@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;



    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignUpRequest signUpRequest) {
        try {
            // Validate input
            if (signUpRequest.getUsername() == null || signUpRequest.getPassword() == null) {
                return new ResponseEntity<>("Username and password are required", HttpStatus.BAD_REQUEST);
            }
            // Check if user input already exists
            else if (userRepository.findByUsername(signUpRequest.getUsername()).isPresent()) {
                return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);
            }
            else {
                // Save the user
                User savingUser = new User();
                savingUser.setUsername(signUpRequest.getUsername());
                savingUser.setPassword(passwordEncoder.encode(signUpRequest.getPassword())); // Ensure password is encoded
                savingUser.setRoles(Set.of(UserRole.valueOf(signUpRequest.getRole().toUpperCase())));
                userService.saveUser(savingUser);
                return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
            }
        }
        catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        catch (Exception e) {
            return new ResponseEntity<>("Error during registration: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
                return new ResponseEntity<>("Username and password are required", HttpStatus.BAD_REQUEST);
            }
            User user = userService.findByUsername(loginRequest.getUsername());
            String password = loginRequest.getPassword();

            if (user == null) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            return ResponseEntity.ok(userService.doAuthenticate(user, password));


        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
