package attendancemanagement.web_security_analysis.service;

import attendancemanagement.web_security_analysis.model.AuthResponse;
import attendancemanagement.web_security_analysis.model.LoginRequest;
import attendancemanagement.web_security_analysis.security.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.AuthenticationManager;
import attendancemanagement.web_security_analysis.model.User;
import attendancemanagement.web_security_analysis.repository.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTTokenProvider tokenProvider;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthResponse doAuthenticate(User user, String password){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwtToken = tokenProvider.generateToken(authentication);
        AuthResponse authResponse = new AuthResponse(
                user.getId(),
                user.getUsername(),
                jwtToken,
                user.getRoles().toString(),
                tokenProvider.getJwtExpirationInMs()
        );
        return authResponse;
    }

    public User saveUser(User user) {
        // Validate input before processing
        if (user == null || user.getUsername() == null || user.getPassword() == null) {
            throw new IllegalArgumentException("User or required fields are null");
        }

        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username cannot be null");
        }
        return userRepository.findByUsername(username).orElse(null);
    }
}
