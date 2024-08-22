package attendancemanagement.web_security_analysis.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import attendancemanagement.web_security_analysis.model.User;
import attendancemanagement.web_security_analysis.repository.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User saveUser(User user) {
        // Validate input before processing
        if (user == null || user.getUsername() == null || user.getPassword() == null) {
            throw new IllegalArgumentException("User or required fields are null");
        }

        // Hash the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username cannot be null");
        }
        return userRepository.findByUsername(username).orElse(null);
    }
}
