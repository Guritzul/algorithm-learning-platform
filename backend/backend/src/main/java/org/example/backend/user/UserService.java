package org.example.backend.user;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.example.backend.registration.token.ConfirmationToken;
import org.example.backend.registration.token.ConfirmationTokenRepository;
import org.example.backend.registration.token.ConfirmationTokenService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MESSAGE = "User with id %s not found";
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @Getter
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MESSAGE, email)));
    }

    public String signUpUser(User user) {
            boolean userExists = userRepository.findByEmail(user.getEmail()).isPresent();
        if (userExists) {
            throw new IllegalStateException("User with email " + user.getEmail() + " already exists");
        }

        String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);

        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token, LocalDateTime.now(),LocalDateTime.now().plusMinutes(15),user
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        return token;
    }
    public void enableUser(String email) {
        userRepository.enableUser(email);
    }

}
