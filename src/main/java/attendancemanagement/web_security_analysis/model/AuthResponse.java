package attendancemanagement.web_security_analysis.model;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@ToString
public class AuthResponse {
        private Long id;
        private String username;
        private String token;
        private String role;
        private long expirationTime;

    }
