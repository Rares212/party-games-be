package com.mps.partygames.security;

import com.mps.partygames.service.AppUserService;
import com.mps.partygames.util.JwtConstants;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private AppUserService userService;
    @Autowired
    private JwtTokenProvider tokenProvider;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(JwtConstants.HEADER_NAME);
        String username = null;
        String authToken = null;
        if (header != null && header.startsWith(JwtConstants.TOKEN_PREFIX)) {
            authToken = header.replace(JwtConstants.TOKEN_PREFIX, "");
            try {
                username = tokenProvider.getUsernameFromToken(authToken);
            } catch (ExpiredJwtException e) {
                logger.warn("JWT token expired");
            } catch (SignatureException e) {
                logger.error("Authentication failed. Username or password not valid");
            } catch (IllegalArgumentException e) {
                logger.error("Error occurred getting the username from token");
            }
        } else {
            logger.warn("Couldn't find bearer string - will ignore the header");
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userService.loadUserByUsername(username);

            if (tokenProvider.validateToken(authToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = tokenProvider.getAuthToken(
                        authToken,
                        SecurityContextHolder.getContext().getAuthentication(),
                        userDetails
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                logger.info("Authenticated user " + username + ", setting security context");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}
