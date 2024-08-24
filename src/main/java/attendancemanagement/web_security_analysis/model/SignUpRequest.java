package attendancemanagement.web_security_analysis.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    private String username;


    @NotBlank
    @Size(min = 6, max = 40)
    private String password;

    @NotBlank
    private String role;
}