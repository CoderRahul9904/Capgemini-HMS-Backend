package com.capgemini.hms.auth.controller.api;

import com.capgemini.hms.auth.entity.ERole;
import com.capgemini.hms.auth.entity.Role;
import com.capgemini.hms.auth.entity.User;
import com.capgemini.hms.auth.payload.request.SignupRequest;
import com.capgemini.hms.auth.payload.response.MessageResponse;
import com.capgemini.hms.auth.repository.RoleRepository;
import com.capgemini.hms.auth.repository.UserRepository;
import com.capgemini.hms.common.dto.ApiResponse;
import com.capgemini.hms.nurse.repository.NurseRepository;
import com.capgemini.hms.patient.repository.PatientRepository;
import com.capgemini.hms.physician.repository.PhysicianRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "User Authentication", description = "Endpoints for user registration (Login/Logout handled by Spring Security)")
public class AuthController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PhysicianRepository physicianRepository;

    @Autowired
    NurseRepository nurseRepository;

    @Autowired
    PatientRepository patientRepository;

    @Autowired
    PasswordEncoder encoder;

    @PostMapping("/signup")
    @Operation(summary = "Register a new user", description = "Creates a new user account with specified roles. Note: Regular user login is handled by /login endpoint.")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else if (strRoles != null) {
            for (String role : strRoles) {
                switch (role.toLowerCase()) {
                    case "admin":
                        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                        if (auth == null || auth.getAuthorities().stream()
                                .noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                            return ResponseEntity
                                    .status(HttpStatus.FORBIDDEN)
                                    .body(new MessageResponse("Error: Only an authenticated Admin can register another Admin."));
                        }
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "doctor":
                        Role doctorRole = roleRepository.findByName(ERole.ROLE_DOCTOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(doctorRole);
                        
                        if (signUpRequest.getStaffId() == null) {
                            throw new RuntimeException("Error: Staff ID is required for doctor role.");
                        }
                        if (!physicianRepository.existsById(signUpRequest.getStaffId())) {
                            throw new RuntimeException("Error: Provided Staff ID is not registered as a Physician.");
                        }
                        user.setStaffId(signUpRequest.getStaffId());
                        break;
                    case "nurse":
                        Role nurseRole = roleRepository.findByName(ERole.ROLE_NURSE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(nurseRole);
                        
                        if (signUpRequest.getStaffId() == null) {
                            throw new RuntimeException("Error: Staff ID is required for nurse role.");
                        }
                        if (!nurseRepository.existsById(signUpRequest.getStaffId())) {
                            throw new RuntimeException("Error: Provided Staff ID is not registered as a Nurse.");
                        }
                        user.setStaffId(signUpRequest.getStaffId());
                        break;
                    case "patient":
                        Role patientRole = roleRepository.findByName(ERole.ROLE_PATIENT)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(patientRole);
                        
                        // Link to clinical patient record
                        if (signUpRequest.getPatientSsn() == null) {
                            throw new RuntimeException("Error: Patient SSN is required for patient role.");
                        }
                        if (!patientRepository.existsById(signUpRequest.getPatientSsn())) {
                            throw new RuntimeException("Error: No clinical record found for SSN: " + signUpRequest.getPatientSsn());
                        }
                        user.setPatientSsn(signUpRequest.getPatientSsn());
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            }
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(ApiResponse.success("User registered successfully!"));
    }
}
