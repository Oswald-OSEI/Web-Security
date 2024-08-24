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
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import attendancemanagement.web_security_analysis.service.CustomUserDetailsService;

@Component
public class CustomAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JWTTokenProvider tokenProvider;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Extract the username and password from the request headers
       try{ String jwt = getJwtFromRequest(request);
           System.out.println("Extracted JWT: " + jwt);
           if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
               String username = tokenProvider.getUsernameFromJWT(jwt);
               System.out.println("Username from JWT: " + username);


               UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
               UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
               authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

               SecurityContextHolder.getContext().setAuthentication(authentication);
               System.out.println("Authentication set in SecurityContext");
        }else {
               System.out.println("Invalid JWT or JWT not present");
           }
       }catch (Exception ex) {
               logger.error("Could not set user authentication in security context", ex);
               response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
               response.getWriter().write("Invalid credentials");
           }

           filterChain.doFilter(request, response);

    }
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}