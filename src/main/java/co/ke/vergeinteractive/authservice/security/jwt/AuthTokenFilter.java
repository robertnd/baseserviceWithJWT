package co.ke.vergeinteractive.authservice.security.jwt;

import co.ke.vergeinteractive.authservice.security.services.UserDetailsServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import org.javatuples.Pair;
import org.springframework.http.HttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {

            Pair<Optional<Exception>, Optional<Jws<Claims>>> parseResult = parseJwt2(request);
            if (parseResult.getValue0().isPresent()) {
                throw parseResult.getValue0().get();
            } else {

                Jws<Claims> claims = parseResult.getValue1().get();
                String username = jwtUtils.getUserName(claims);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            //TODO: cleanup
//            String jwt = parseJwt(request);
//            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
//                String username = jwtUtils.getUserNameFromJwtToken(jwt);
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                UsernamePasswordAuthenticationToken authentication =
//                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    //TODO: clean this up
    /*
    private String parseJwt(HttpServletRequest request) {

        Map<String, String> headers = Collections.list(request.getHeaderNames())
                .stream()
                .collect(Collectors.toMap(h -> h, request::getHeader));

        String token = headers.containsKey("Authorization") ? Objects.requireNonNull(headers.get("Authorization")) : "";
        String strippedToken = token.startsWith("Bearer ") ? token.replace("Bearer ", "") : token;
        String jwt = strippedToken.isBlank() ? "" : jwtUtils.getUserNameFromJwtToken(strippedToken);
        return jwt;
    }

     */

    private Optional<Jws<Claims>> parseJwt(HttpServletRequest request) {

        Map<String, String> headers = Collections.list(request.getHeaderNames())
                .stream()
                .collect(Collectors.toMap(h -> h, request::getHeader));

        String token = headers.containsKey("Authorization") ? Objects.requireNonNull(headers.get("Authorization")) : "";
        String strippedToken = token.startsWith("Bearer ") ? token.replace("Bearer ", "") : token;

        return strippedToken.isBlank()
                ? Optional.empty()
                : Optional.ofNullable(jwtUtils.getClaims(strippedToken));
    }

    private Pair<Optional<Exception>, Optional<Jws<Claims>>> parseJwt2(HttpServletRequest request) {

        // On Pair<> : The "left" will contain the error, the "right" will contain the value.
        // This is following a long held humorous convention from the world of Scala FP (Scala.Either)

        Map<String, String> headers = Collections.list(request.getHeaderNames())
                .stream()
                .collect(Collectors.toMap(h -> h, request::getHeader));

        String token = headers.containsKey("Authorization") ? Objects.requireNonNull(headers.get("Authorization")) : "";
        String strippedToken = token.startsWith("Bearer ") ? token.replace("Bearer ", "") : token;

        if ( strippedToken.isBlank() ) {
            return new Pair<>(Optional.ofNullable(new Exception("Token is blank")), Optional.empty());
        } else {
            try {
                Jws<Claims> claims = jwtUtils.getClaims(strippedToken);
                return new Pair<>(Optional.empty(), Optional.ofNullable(claims));
            } catch (Exception e) {
                return new Pair<>(Optional.ofNullable(e), Optional.empty());
            }
        }
    }
}
