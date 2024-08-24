package attendancemanagement.web_security_analysis.controller;
import attendancemanagement.web_security_analysis.model.LoginRequest;
import attendancemanagement.web_security_analysis.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import attendancemanagement.web_security_analysis.model.User;
import attendancemanagement.web_security_analysis.service.UserService;

@RestController
@RequestMapping("/admin")
public class AdminController {
    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;


    @PostMapping("/addUser")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<String> signup(@RequestBody User user) {
        try {
            // Validate input
            if (user.getUsername() == null || user.getPassword() == null) {
                return new ResponseEntity<>("Username and password are required", HttpStatus.BAD_REQUEST);
            }
            //check if user input already exists
            else if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);
            }
            else {
                // Save the user
                userService.saveUser(user);
                return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
            }
        }

        //if any of the input fields was left blank
        catch (Exception e) {
            return new ResponseEntity<>("Error during registration: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


}
