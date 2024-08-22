package attendancemanagement.web_security_analysis.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import attendancemanagement.web_security_analysis.service.CustomUserDetailsService;

@Component
public class CustomAuthFilter extends OncePerRequestFilter {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


        // Extract the username and password from the request headers
        String username = request.getHeader("Username");
        String password = request.getHeader("Password");

        if (username != null && password != null) {
            try {
                // Load the user details from the custom user details service
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                // Create an authentication token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, password, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } catch (Exception e) {
                // Log the exception
                logger.error("Authentication error: ", e);
                // Handle any exceptions that occur during authentication
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid credentials");
                return;
            }
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}