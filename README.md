package com.skyboy.streams;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// --- Imports for Token Generation ---
import io.agora.media.RtcTokenBuilder;
import io.agora.media.RtcTokenBuilder.Role;
import org.springframework.beans.factory.annotation.Value;

// --- Imports for Data/DB (NOTE: These classes must exist separately) ---
import your.package.here.model.User; 
import your.package.here.repository.UserRepository;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

// =================================================================
// DATA STRUCTURES (Used by the APIs)
// =================================================================
record LoginRequest(String username, String password) {}
record RegistrationRequest(String username, String email, String password) {}

// =================================================================
// 1. AUTH SERVICE (The Logic: Register & Login)
// =================================================================
// NOTE: This class replaces your separate UserService.java file.
@Service 
class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // [Your Existing Registration Logic is here]
    public Optional<User> registerNewUser(String username, String email, String rawPassword) {
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            return Optional.empty(); 
        }
        String hashedPassword = passwordEncoder.encode(rawPassword);
        User newUser = new User(username, email, hashedPassword);
        newUser.setStreamer(false); 
        return Optional.of(userRepository.save(newUser));
    }

    /**
     * Securely authenticates a user (The Login Fix).
     */
    public Optional<User> authenticateUser(String username, String rawPassword) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // CRITICAL security check
            if (passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
                return Optional.of(user); 
            }
        }
        return Optional.empty(); 
    }
}

// =================================================================
// 2. AUTH CONTROLLER (The API Endpoints: Token, Register, Login)
// =================================================================
// NOTE: This class replaces your TokenController.java and RegistrationController.java files.
@RestController
@CrossOrigin(origins = "*") 
class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final AuthService authService; // Uses the service defined above

    @Value("${agora.appId}") private String appId;
    @Value("${agora.appCertificate}") private String appCertificate;
    @Value("${agora.tokenExpiration:3600}") private int tokenExpirationSeconds;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // --- API 1: AGORA TOKEN GENERATION (/api/agora/token) ---
    @GetMapping("/api/agora/token")
    public ResponseEntity<Map<String, String>> generateRtcToken(
            @RequestParam("channel") String channelName,
            @RequestParam(value = "uid", required = false, defaultValue = "0") int uid,
            @RequestParam(value = "role", required = false, defaultValue = "audience") String roleString) {

        try {
            RtcTokenBuilder tokenBuilder = new RtcTokenBuilder();
            Role role = "publisher".equalsIgnoreCase(roleString) ? Role.Rtc_Publisher : Role.Rtc_Subscriber;
            int currentTs = (int) (System.currentTimeMillis() / 1000);
            int privilegeExpiredTs = currentTs + tokenExpirationSeconds;

            String token = tokenBuilder.buildTokenWithUid(appId, appCertificate, channelName, uid, role, privilegeExpiredTs);
            return ResponseEntity.ok(Collections.singletonMap("token", token));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "Failed to generate token"));
        }
    }

    // --- API 2: USER REGISTRATION (/api/auth/register) ---
    @PostMapping("/api/auth/register")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody RegistrationRequest request) {
        // [Registration logic calls authService.registerNewUser]
        if (request.username().isBlank() || request.email().isBlank() || request.password().length() < 8) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Required fields are missing or password is too short."));
        }
        
        Optional<User> newUser = authService.registerNewUser(request.username(), request.email(), request.password());

        if (newUser.isPresent()) {
             // Success return map
             return ResponseEntity.status(HttpStatus.CREATED).body(Collections.emptyMap());
        } else {
             return ResponseEntity.status(HttpStatus.CONFLICT).body(Collections.emptyMap());
        }
    }


    // --- API 3: USER LOGIN (/api/auth/login) ---
    @PostMapping("/api/auth/login")
    public ResponseEntity<Map<String, Object>> loginUser(@RequestBody LoginRequest request) {
        if (request.username() == null || request.password() == null) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "Username and password are required."));
        }

        Optional<User> userOpt = authService.authenticateUser(request.username(), request.password());

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Success: Return user details
            return ResponseEntity.ok().body(Map.of("success", true, "userId", user.getUserId().toString()));
        } else {
            // Failure
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Invalid username or password."));
        }
    }
}