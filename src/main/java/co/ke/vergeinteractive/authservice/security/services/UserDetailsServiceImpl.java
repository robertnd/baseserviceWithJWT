package co.ke.vergeinteractive.authservice.security.services;

import co.ke.vergeinteractive.authservice.model.dto.UserDetailsImpl;
import co.ke.vergeinteractive.authservice.model.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    //private final UserRepository userRepository;
    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Override
    //@Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        /*User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
         */
        //TODO: simulated users
        User user = null;
        switch(username) {
            case "intermed@nosuchmail.org":
            case "intermed":
                user = new User( "intermed", "intermed@nosuchmail.org", passwordEncoder.encode("intermed"));
                break;
            case "supervisor@nosuchmail.org":
            case "supervisor":
                user = new User( "supervisor", "supervisor@nosuchmail.org", passwordEncoder.encode("supervisor"));
                break;
            default:
                user = new User( "guest", "guest@nosuchmail.org", passwordEncoder.encode("guest"));
                break;
        }
        return UserDetailsImpl.build(user);
    }
}
