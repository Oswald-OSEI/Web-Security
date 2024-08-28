package attendancemanagement.web_security_analysis.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;



@Controller
@RequestMapping
public class AuthController {

    @GetMapping("/")
    public String home(){
        return "home";
    
    }
    
    @GetMapping("/login")
    public String secured() {
        return "login";
    }

}    