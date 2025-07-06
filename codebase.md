# lims-auth-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.lims</groupId>
        <artifactId>lims-system</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>lims-auth-service</artifactId>
    <packaging>jar</packaging>

    <name>LIMS Authentication Service</name>
    <description>Authentication and Authorization service for LIMS</description>

    <dependencies>
        <!-- Spring Boot Starters -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- PostgreSQL Driver -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- H2 Database pour les tests -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- Spring Security OAuth2 JOSE -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-jose</artifactId>
        </dependency>

        <!-- ✅ Keycloak Admin Client avec version compatible -->
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-admin-client</artifactId>
            <version>26.0.5</version>
        </dependency>

        <!-- ✅ JAX-RS API pour compatibilité Keycloak -->
        <dependency>
            <groupId>javax.ws.rs</groupId>
            <artifactId>javax.ws.rs-api</artifactId>
            <version>2.1.1</version>
        </dependency>

        <!-- ✅ RESTEasy Client pour Keycloak -->
        <dependency>
            <groupId>org.jboss.resteasy</groupId>
            <artifactId>resteasy-client</artifactId>
            <version>6.2.8.Final</version>
        </dependency>

        <dependency>
            <groupId>org.jboss.resteasy</groupId>
            <artifactId>resteasy-jackson2-provider</artifactId>
            <version>6.2.8.Final</version>
        </dependency>

        <!-- ✅ RESTEasy Core pour runtime -->
        <dependency>
            <groupId>org.jboss.resteasy</groupId>
            <artifactId>resteasy-core</artifactId>
            <version>6.2.8.Final</version>
        </dependency>

        <!-- TOTP / Google Authenticator -->
        <dependency>
            <groupId>dev.samstevens.totp</groupId>
            <artifactId>totp</artifactId>
            <version>1.7.1</version>
        </dependency>

        <!-- QR Code Generation -->
        <dependency>
            <groupId>com.google.zxing</groupId>
            <artifactId>core</artifactId>
            <version>3.5.1</version>
        </dependency>
        <dependency>
            <groupId>com.google.zxing</groupId>
            <artifactId>javase</artifactId>
            <version>3.5.1</version>
        </dependency>

        <!-- OpenAPI Documentation -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>2.2.0</version>
        </dependency>

        <!-- JSON Processing -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>

        <!-- ✅ JWT Token Processing -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.6</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.6</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.12.6</version>
            <scope>runtime</scope>
        </dependency>

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- MapStruct (dernière version stable) -->
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>1.6.3</version>
        </dependency>

        <!-- Development Tools -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>postgresql</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>

            <!-- Maven Compiler Plugin avec MapStruct -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <source>21</source>
                    <target>21</target>
                    <annotationProcessorPaths>
                        <path>
                            <groupId>org.mapstruct</groupId>
                            <artifactId>mapstruct-processor</artifactId>
                            <version>1.6.3</version>
                        </path>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                            <version>1.18.30</version>
                        </path>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok-mapstruct-binding</artifactId>
                            <version>0.2.0</version>
                        </path>
                    </annotationProcessorPaths>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

# lims-auth-service/src/main/java/com/lims/auth/AuthServiceApplication.java

```java
package com.lims.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/config/AdminJwtAuthenticationConverter.java

```java
package com.lims.auth.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class AdminJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public AdminJwtAuthenticationConverter() {
        // Configurer le converter pour extraire les authorities customisées
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Vérifier que le JWT provient du realm lims-admin
        String realm = jwt.getClaimAsString("realm");
        if (!"lims-admin".equals(realm)) {
            throw new IllegalArgumentException("Invalid realm: " + realm);
        }

        String userType = jwt.getClaimAsString("user_type");
        if (!"ADMIN".equals(userType)) {
            throw new IllegalArgumentException("Invalid user type: " + userType);
        }

        // Extraire les authorities par défaut
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

        // Ajouter les rôles spécifiques au realm admin
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                Collection<GrantedAuthority> realmAuthorities = roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Combiner les authorities
                return Stream.concat(authorities.stream(), realmAuthorities.stream())
                        .collect(Collectors.toList());
            }
        }

        return authorities;
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/config/AdminSecurityConfig.java

```java
package com.lims.auth.config;

import com.lims.auth.security.AdminSecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class AdminSecurityConfig {

    /**
     * Bean pour AdminSecurityContext afin de l'utiliser dans les annotations PreAuthorize
     */
    @Bean
    public AdminSecurityContext adminSecurityContext() {
        return new AdminSecurityContext();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/config/KeycloakConfig.java

```java
package com.lims.auth.config;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(name = "keycloak.enabled", havingValue = "true", matchIfMissing = false)
public class KeycloakConfig {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloakClient() {
        try {
            return KeycloakBuilder.builder()
                    .serverUrl(authServerUrl)
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Keycloak client", e);
        }
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/config/LimsAuthProperties.java

```java
package com.lims.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "lims.auth")
@Data
public class LimsAuthProperties {

    private Mfa mfa = new Mfa();
    private RateLimit rateLimit = new RateLimit();
    private Session session = new Session();
    private Security security = new Security();
    private Jwt jwt = new Jwt();

    @Data
    public static class Mfa {
        private String issuer = "LIMS-Admin-System";
        private BackupCodes backupCodes = new BackupCodes();
        private int setupTokenExpiry = 600; // 10 minutes
        private int resetTokenExpiry = 86400; // 24 heures

        @Data
        public static class BackupCodes {
            private int count = 10;
            private int length = 8;
        }
    }

    @Data
    public static class RateLimit {
        private int maxAttempts = 5;
        private int windowMinutes = 15;
        private int lockoutDurationMinutes = 30;
    }

    @Data
    public static class Session {
        private int timeout = 7200; // 2 heures
        private boolean extendOnActivity = true;
        private int maxConcurrentSessions = 3;
        private int cleanupIntervalMinutes = 60;
    }

    @Data
    public static class Security {
        private int maxFailedAttempts = 3;
        private int lockoutDurationMinutes = 30;
        private int passwordResetTokenExpiry = 86400; // 24 heures
        private int maxPasswordResetRequests = 3;
        private int passwordResetCooldownMinutes = 60;
    }

    @Data
    public static class Jwt {
        private String secret = "default-secret-key-for-development-only-change-in-production";
        private int accessTokenValidity = 3600; // 1 heure
        private int refreshTokenValidity = 86400; // 24 heures
        private String issuer = "lims-auth-service";
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/config/MapStructConfig.java

```java
package com.lims.auth.config;

import org.mapstruct.MapperConfig;
import org.mapstruct.MappingConstants;
import org.mapstruct.ReportingPolicy;

@MapperConfig(
        componentModel = MappingConstants.ComponentModel.SPRING,
        unmappedTargetPolicy = ReportingPolicy.WARN,
        typeConversionPolicy = ReportingPolicy.ERROR
)
public interface MapStructConfig {
    // Configuration globale pour tous les mappers
}
```

# lims-auth-service/src/main/java/com/lims/auth/config/RedisConfig.java

```java
package com.lims.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.Map;

@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Utiliser String pour les clés
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());

        // Utiliser JSON pour les valeurs
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());

        template.afterPropertiesSet();
        return template;
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/config/SecurityConfig.java

```java
package com.lims.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // Endpoints publics (pas d'authentification)
                        .requestMatchers(
                                "/api/v1/auth/hello",
                                "/actuator/health",
                                "/actuator/info",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        // Endpoints de setup MFA (utilisation de tokens temporaires)
                        .requestMatchers(
                                "/api/v1/auth/admin/mfa/setup",
                                "/api/v1/auth/admin/setup/verify",
                                "/api/v1/auth/admin/mfa/setup/verify/**",
                                "/api/v1/auth/admin/mfa/setup/**",
                                "/api/v1/auth/admin/mfa/reset/*/",
                                "/api/v1/auth/admin/mfa/reset/*/complete"
                        ).permitAll()

                        // Endpoints de login (pas d'authentification mais validation custom)
                        .requestMatchers(
                                "/api/v1/auth/admin/login",
                                "/api/v1/auth/admin/refresh",
                                "/api/v1/auth/admin/mfa/reset/request"
                        ).permitAll()

                        // Tous les autres endpoints admin nécessitent une authentification
                        .requestMatchers("/api/v1/auth/admin/**").authenticated()

                        // Fallback : toute autre requête nécessite une authentification
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new AdminJwtAuthenticationConverter();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


```

# lims-auth-service/src/main/java/com/lims/auth/config/TotpConfig.java

```java
package com.lims.auth.config;

import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TotpConfig {
    @Bean
    public SecretGenerator secretGenerator() {
        return new DefaultSecretGenerator();
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/controller/AdminAuthController.java

```java
package com.lims.auth.controller;

import com.lims.auth.dto.request.AdminLoginRequest;
import com.lims.auth.dto.request.AdminMfaSetupRequest;
import com.lims.auth.dto.request.AdminMfaVerifyRequest;
import com.lims.auth.dto.request.AdminRefreshTokenRequest;
import com.lims.auth.dto.request.AdminLogoutRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminMfaSetupResponse;
import com.lims.auth.dto.response.AdminTokenResponse;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.service.AdminAuthenticationService;
import com.lims.auth.service.AdminMfaService;
import com.lims.auth.service.AdminTokenService;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.MfaException;
import com.lims.auth.exception.RateLimitException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth/admin")
@Tag(name = "Admin Authentication", description = "Endpoints d'authentification pour les administrateurs LIMS")
@RequiredArgsConstructor
@Slf4j
@Validated
public class AdminAuthController {

    private final AdminAuthenticationService adminAuthService;
    private final AdminMfaService adminMfaService;
    private final AdminTokenService adminTokenService;

    @Operation(summary = "Connexion administrateur", description = "Authentifie un administrateur avec email/mot de passe et MFA obligatoire. " + "Premier login nécessite setup MFA avec Google Authenticator.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Connexion réussie"), @ApiResponse(responseCode = "401", description = "Identifiants invalides"), @ApiResponse(responseCode = "429", description = "Trop de tentatives - Rate limiting actif"), @ApiResponse(responseCode = "423", description = "Compte temporairement verrouillé")})
    @PostMapping("/login")
    public ResponseEntity<AdminLoginResponse> login(@Valid @RequestBody AdminLoginRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Tentative de connexion admin - Email: {}, IP: {}", request.getEmail(), clientIp);

        try {
            AdminLoginResponse response = adminAuthService.authenticate(request, clientIp, userAgent);

            if (response.isRequiresMfaSetup()) {
                log.info("Premier login admin détecté - Setup MFA requis - Email: {}", request.getEmail());
                return ResponseEntity.ok(response);
            }

            if (response.isSuccess()) {
                log.info("Connexion admin réussie - Email: {}, SessionId: {}", request.getEmail(), response.getSessionId());
                return ResponseEntity.ok(response);
            }

            log.warn("Échec connexion admin - Email: {}, Raison: {}", request.getEmail(), response.getErrorMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);

        } catch (RateLimitException e) {
            log.warn("Rate limiting actif pour admin - Email: {}, IP: {}", request.getEmail(), clientIp);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(AdminLoginResponse.rateLimitExceeded(e.getMessage()));

        } catch (AuthenticationException e) {
            log.error("Erreur authentification admin - Email: {}, Erreur: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AdminLoginResponse.failed(e.getMessage()));

        } catch (Exception e) {
            log.error("Erreur inattendue lors connexion admin - Email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(AdminLoginResponse.failed("Erreur technique temporaire"));
        }
    }

    @Operation(summary = "Setup MFA - Génération QR Code", description = "Génère un QR Code Google Authenticator pour le setup initial MFA. " + "Utilise un token temporaire de setup.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "QR Code généré avec succès"), @ApiResponse(responseCode = "400", description = "Token setup invalide ou expiré"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/mfa/setup")
    public ResponseEntity<AdminMfaSetupResponse> setupMfa(@Parameter(description = "Token de setup MFA temporaire", required = true) @RequestParam("setupToken") String setupToken) {

        log.info("Demande setup MFA - Token: {}", setupToken.substring(0, 8) + "...");

        try {
            AdminMfaSetupResponse response = adminMfaService.generateMfaSetup(setupToken);

            log.info("QR Code MFA généré - Token: {}", setupToken.substring(0, 8) + "...");
            return ResponseEntity.ok(response);

        } catch (MfaException e) {
            log.error("Erreur génération QR Code MFA - Token: {}, Erreur: {}", setupToken.substring(0, 8) + "...", e.getMessage());
            return ResponseEntity.badRequest().body(AdminMfaSetupResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Vérification Setup MFA", description = "Valide le premier code OTP généré par Google Authenticator et finalise le setup MFA. " + "Génère les codes de récupération et connecte automatiquement l'utilisateur.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Setup MFA complété avec succès"), @ApiResponse(responseCode = "400", description = "Code OTP invalide"), @ApiResponse(responseCode = "401", description = "Token setup invalide")})
    @PostMapping("/mfa/setup/verify")
    public ResponseEntity<AdminLoginResponse> verifyMfaSetup(@Valid @RequestBody AdminMfaVerifyRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        log.info("Vérification setup MFA - Token: {}", request.getSetupToken().substring(0, 8) + "...");

        try {
            AdminLoginResponse response = adminMfaService.verifyMfaSetup(request, clientIp, userAgent);

            if (response.isSuccess()) {
                log.info("Setup MFA complété avec succès - SessionId: {}", response.getSessionId());
                return ResponseEntity.ok(response);
            }

            log.warn("Échec vérification setup MFA - Raison: {}", response.getErrorMessage());
            return ResponseEntity.badRequest().body(response);

        } catch (MfaException e) {
            log.error("Erreur vérification setup MFA - Erreur: {}", e.getMessage());
            return ResponseEntity.badRequest().body(AdminLoginResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Rafraîchissement token", description = "Génère un nouveau token d'accès à partir du refresh token valide.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Token rafraîchi avec succès"), @ApiResponse(responseCode = "401", description = "Refresh token invalide ou expiré")})
    @PostMapping("/refresh")
    public ResponseEntity<AdminTokenResponse> refreshToken(@Valid @RequestBody AdminRefreshTokenRequest request, HttpServletRequest httpRequest) {

        String clientIp = getClientIp(httpRequest);

        log.debug("Demande rafraîchissement token - IP: {}", clientIp);

        try {
            AdminTokenResponse response = adminTokenService.refreshToken(request.getRefreshToken(), clientIp);

            log.debug("Token rafraîchi avec succès");
            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            log.warn("Échec rafraîchissement token - Erreur: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(AdminTokenResponse.failed(e.getMessage()));
        }
    }

    @Operation(summary = "Déconnexion administrateur", description = "Déconnecte l'administrateur, invalide la session et révoque les tokens.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Déconnexion réussie"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @PostMapping("/logout")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> logout(@Valid @RequestBody AdminLogoutRequest request, @AuthenticationPrincipal Jwt jwt, HttpServletRequest httpRequest) {

        String adminId = jwt.getSubject();
        String clientIp = getClientIp(httpRequest);

        log.info("Déconnexion admin - AdminId: {}, SessionId: {}", adminId, request.getSessionId());

        try {
            adminAuthService.logout(adminId, request.getSessionId(), clientIp);

            log.info("Déconnexion admin réussie - AdminId: {}", adminId);
            return ResponseEntity.ok(Map.of("success", true, "message", "Déconnexion réussie"));

        } catch (Exception e) {
            log.error("Erreur déconnexion admin - AdminId: {}", adminId, e);
            return ResponseEntity.ok(Map.of("success", false, "message", "Erreur lors de la déconnexion"));
        }
    }

    @Operation(summary = "Informations administrateur connecté", description = "Retourne les informations de l'administrateur actuellement connecté.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Informations récupérées"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/me")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<AdminUserResponse> getCurrentAdmin(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération informations admin - AdminId: {}", adminId);

        try {
            AdminUserResponse response = adminAuthService.getCurrentAdmin(adminId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Erreur récupération informations admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Operation(summary = "Permissions administrateur", description = "Retourne les permissions de l'administrateur connecté.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Permissions récupérées"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/permissions")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> getAdminPermissions(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération permissions admin - AdminId: {}", adminId);

        try {
            Map<String, Object> permissions = adminAuthService.getAdminPermissions(adminId);
            return ResponseEntity.ok(permissions);

        } catch (Exception e) {
            log.error("Erreur récupération permissions admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Operation(summary = "Statut de session", description = "Retourne le statut de la session courante de l'administrateur.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Statut de session récupéré"), @ApiResponse(responseCode = "401", description = "Non autorisé")})
    @GetMapping("/session/status")
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Map<String, Object>> getSessionStatus(@AuthenticationPrincipal Jwt jwt) {

        String adminId = jwt.getSubject();

        log.debug("Récupération statut session admin - AdminId: {}", adminId);

        try {
            Map<String, Object> sessionStatus = adminTokenService.getSessionStatus(adminId);
            return ResponseEntity.ok(sessionStatus);

        } catch (Exception e) {
            log.error("Erreur récupération statut session admin - AdminId: {}", adminId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Extraction de l'adresse IP du client
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/controller/AuthController.java

```java
package com.lims.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @GetMapping("/hello")
    public ResponseEntity<Map<String, Object>> hello() {
        return ResponseEntity.ok(Map.of(
                "message", "Hello from LIMS Authentication Service!",
                "service", "lims-auth-service",
                "timestamp", LocalDateTime.now(),
                "port", 8081
        ));
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/request/AdminLoginRequest.java

```java
package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de connexion administrateur")
public class AdminLoginRequest {

    @NotBlank(message = "L'email est obligatoire")
    @Email(message = "Format d'email invalide")
    @Size(max = 255, message = "L'email ne peut pas dépasser 255 caractères")
    @Schema(description = "Adresse email de l'administrateur", example = "admin@lims.local", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @NotBlank(message = "Le mot de passe est obligatoire")
    @Size(min = 8, max = 128, message = "Le mot de passe doit contenir entre 8 et 128 caractères")
    @Schema(description = "Mot de passe", example = "SuperSecretPassword123!", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;

    @Pattern(regexp = "^[0-9]{6}$", message = "Le code OTP doit contenir exactement 6 chiffres")
    @Schema(description = "Code OTP Google Authenticator (6 chiffres)", example = "123456", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    @JsonProperty("otpCode")
    private String otpCode;

    @Schema(description = "Indicateur de connexion depuis un appareil de confiance", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean rememberDevice = false;
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/request/AdminLogoutRequest.java

```java
package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de déconnexion")
public class AdminLogoutRequest {

    @NotBlank(message = "L'ID de session est obligatoire")
    @Schema(description = "ID de session à invalider",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String sessionId;
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/request/AdminMfaSetupRequest.java

```java
package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de setup MFA")
public class AdminMfaSetupRequest {

    @NotBlank(message = "Le token de setup est obligatoire")
    @Schema(description = "Token de setup MFA temporaire",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String setupToken;
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/request/AdminMfaVerifyRequest.java

```java
package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de vérification MFA")
public class AdminMfaVerifyRequest {

    @NotBlank(message = "Le code OTP est obligatoire")
    @Pattern(regexp = "^[0-9]{6}$", message = "Le code OTP doit contenir exactement 6 chiffres")
    @Schema(description = "Code OTP Google Authenticator",
            example = "123456",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String otpCode;

    @NotBlank(message = "Le token de setup est obligatoire")
    @Schema(description = "Token de setup MFA temporaire",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String setupToken;
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/request/AdminRefreshTokenRequest.java

```java
package com.lims.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Requête de rafraîchissement token")
public class AdminRefreshTokenRequest {

    @NotBlank(message = "Le refresh token est obligatoire")
    @Schema(description = "Token de rafraîchissement",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String refreshToken;
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/response/AdminLoginResponse.java

```java
package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de connexion administrateur")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminLoginResponse {

    @Schema(description = "Succès de la connexion")
    private boolean success;

    @Schema(description = "Setup MFA requis pour premier login")
    @JsonProperty("requiresMfaSetup")
    private boolean requiresMfaSetup;

    @Schema(description = "Token temporaire pour setup MFA")
    private String setupToken;

    @Schema(description = "Token d'accès JWT")
    private String accessToken;

    @Schema(description = "Token de rafraîchissement")
    private String refreshToken;

    @Schema(description = "ID de session")
    private String sessionId;

    @Schema(description = "Informations utilisateur")
    private AdminUserInfo user;

    @Schema(description = "Codes de récupération MFA (uniquement lors du setup)")
    private List<String> backupCodes;

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    @Schema(description = "Code d'erreur")
    private String errorCode;

    @Schema(description = "Durée de validité du token en secondes")
    private Long expiresIn;

    @Schema(description = "Timestamp de la réponse")
    private LocalDateTime timestamp;

    // Méthodes utilitaires statiques
    public static AdminLoginResponse success(String accessToken, String refreshToken,
                                             String sessionId, AdminUserInfo user) {
        return AdminLoginResponse.builder()
                .success(true)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .sessionId(sessionId)
                .user(user)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse mfaSetupRequired(String setupToken) {
        return AdminLoginResponse.builder()
                .success(false)
                .requiresMfaSetup(true)
                .setupToken(setupToken)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse failed(String errorMessage) {
        return AdminLoginResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminLoginResponse rateLimitExceeded(String message) {
        return AdminLoginResponse.builder()
                .success(false)
                .errorMessage(message)
                .errorCode("RATE_LIMIT_EXCEEDED")
                .timestamp(LocalDateTime.now())
                .build();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @Schema(description = "Informations utilisateur administrateur")
    public static class AdminUserInfo {
        @Schema(description = "ID unique de l'administrateur")
        private String id;

        @Schema(description = "Adresse email")
        private String email;

        @Schema(description = "Prénom")
        private String firstName;

        @Schema(description = "Nom de famille")
        private String lastName;

        @Schema(description = "Rôle administrateur")
        private String role;

        @Schema(description = "Realm Keycloak")
        private String realm;

        @Schema(description = "Type d'utilisateur")
        private String userType;

        @Schema(description = "Permissions")
        private List<String> permissions;

        @Schema(description = "Statut MFA")
        private boolean mfaEnabled;

        @Schema(description = "Date de dernière connexion")
        private LocalDateTime lastLogin;

        @Schema(description = "Statut du compte")
        private String status;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/response/AdminMfaSetupResponse.java

```java
package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de setup MFA")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminMfaSetupResponse {

    @Schema(description = "Succès de la génération")
    private boolean success;

    @Schema(description = "Image QR Code encodée en Base64")
    private String qrCodeImage;

    @Schema(description = "URL du QR Code")
    private String qrCodeUrl;

    @Schema(description = "Clé secrète (pour debug uniquement)")
    private String secretKey;

    @Schema(description = "Issuer du TOTP")
    private String issuer;

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    public static AdminMfaSetupResponse success(String qrCodeImage, String qrCodeUrl,
                                                String secretKey, String issuer) {
        return AdminMfaSetupResponse.builder()
                .success(true)
                .qrCodeImage(qrCodeImage)
                .qrCodeUrl(qrCodeUrl)
                .secretKey(secretKey)
                .issuer(issuer)
                .build();
    }

    public static AdminMfaSetupResponse failed(String errorMessage) {
        return AdminMfaSetupResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .build();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/response/AdminTokenResponse.java

```java
package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse de token")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminTokenResponse {

    @Schema(description = "Succès de l'opération")
    private boolean success;

    @Schema(description = "Nouveau token d'accès")
    private String accessToken;

    @Schema(description = "Nouveau token de rafraîchissement")
    private String refreshToken;

    @Schema(description = "Durée de validité en secondes")
    private Long expiresIn;

    @Schema(description = "Type de token")
    private String tokenType = "Bearer";

    @Schema(description = "Message d'erreur")
    private String errorMessage;

    @Schema(description = "Timestamp de la réponse")
    private LocalDateTime timestamp;

    public static AdminTokenResponse success(String accessToken, String refreshToken, Long expiresIn) {
        return AdminTokenResponse.builder()
                .success(true)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiresIn)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static AdminTokenResponse failed(String errorMessage) {
        return AdminTokenResponse.builder()
                .success(false)
                .errorMessage(errorMessage)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/dto/response/AdminUserResponse.java

```java
package com.lims.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(description = "Réponse utilisateur administrateur")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminUserResponse {

    @Schema(description = "ID unique de l'administrateur")
    private String id;

    @Schema(description = "Adresse email")
    private String email;

    @Schema(description = "Prénom")
    private String firstName;

    @Schema(description = "Nom de famille")
    private String lastName;

    @Schema(description = "Nom complet")
    private String fullName;

    @Schema(description = "Rôle administrateur")
    private String role;

    @Schema(description = "Realm Keycloak")
    private String realm;

    @Schema(description = "Type d'utilisateur")
    private String userType;

    @Schema(description = "Permissions")
    private List<String> permissions;

    @Schema(description = "Statut MFA")
    private boolean mfaEnabled;

    @Schema(description = "Date de création du compte")
    private LocalDateTime createdAt;

    @Schema(description = "Date de dernière connexion")
    private LocalDateTime lastLogin;

    @Schema(description = "Adresse IP de dernière connexion")
    private String lastLoginIp;

    @Schema(description = "Statut du compte")
    private String status;

    @Schema(description = "Nombre de tentatives de connexion échouées")
    private Integer failedAttempts;

    @Schema(description = "Indicateur de verrouillage temporaire")
    private boolean temporarilyLocked;

    @Schema(description = "Date de fin de verrouillage")
    private LocalDateTime lockedUntil;
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/AdminAuditLog.java

```java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "admin_audit_logs", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_user_id")
    private AdminUser adminUser;

    @Column(name = "action", nullable = false, length = 100)
    private String action;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "client_ip", nullable = false)
    private String clientIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Enumerated(EnumType.STRING)
    @Column(name = "result", nullable = false)
    private AuditResult result;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "session_id", length = 36)
    private String sessionId;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    public enum AuditResult {
        SUCCESS("Succès"),
        FAILURE("Échec"),
        WARNING("Avertissement");

        private final String displayName;

        AuditResult(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/AdminPasswordReset.java

```java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "admin_password_resets", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminPasswordReset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_user_id", nullable = false)
    private AdminUser adminUser;

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String token;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used", nullable = false)
    @Builder.Default
    private Boolean used = false;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "client_ip", nullable = false)
    private String clientIp;

    @Column(name = "reason", length = 500)
    private String reason;

    // Méthodes utilitaires
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }

    public boolean isUsed() {
        return used != null && used;
    }

    public boolean isValid() {
        return !isExpired() && !isUsed();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/AdminSession.java

```java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "admin_sessions", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminSession {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_user_id", nullable = false)
    private AdminUser adminUser;

    @Column(name = "client_ip", nullable = false)
    private String clientIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private Boolean active = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_activity", nullable = false)
    private LocalDateTime lastActivity;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "logout_at")
    private LocalDateTime logoutAt;

    // Méthodes utilitaires
    public boolean isActive() {
        return active != null && active && !isExpired();
    }

    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(LocalDateTime.now());
    }

    public void updateLastActivity() {
        this.lastActivity = LocalDateTime.now();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/AdminUser.java

```java
// AdminUser.java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "admin_users", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AdminUser {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", columnDefinition = "uuid")
    private String id;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private AdminRole role;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "admin_user_permissions", schema = "lims_auth",
            joinColumns = @JoinColumn(name = "admin_user_id"))
    @Column(name = "permission")
    private List<String> permissions;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private AdminStatus status = AdminStatus.ACTIVE;

    @Column(name = "mfa_enabled", nullable = false)
    @Builder.Default
    private Boolean mfaEnabled = false;

    @Column(name = "mfa_setup_at")
    private LocalDateTime mfaSetupAt;

    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private Integer failedAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    @Column(name = "last_login_ip")
    private String lastLoginIp;

    @Column(name = "created_by")
    private String createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "keycloak_id")
    private String keycloakId;

    // Méthodes utilitaires
    public boolean isEnabled() {
        return enabled != null && enabled;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled != null && mfaEnabled;
    }

    public boolean isTemporarilyLocked() {
        return lockedUntil != null && lockedUntil.isAfter(LocalDateTime.now());
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public enum AdminRole {
        SUPER_ADMIN("Super Administrateur"),
        SYSTEM_ADMIN("Administrateur Système"),
        USER_ADMIN("Administrateur Utilisateurs"),
        AUDIT_ADMIN("Administrateur Audit");

        private final String displayName;

        AdminRole(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    public enum AdminStatus {
        ACTIVE("Actif"),
        INACTIVE("Inactif"),
        SUSPENDED("Suspendu"),
        LOCKED("Verrouillé");

        private final String displayName;

        AdminStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/MfaBackupCode.java

```java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "mfa_backup_codes", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaBackupCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_user_id", nullable = false)
    private AdminUser adminUser;

    @Column(name = "code", nullable = false, length = 10)
    private String code;

    @Column(name = "used", nullable = false)
    @Builder.Default
    private Boolean used = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    // Méthodes utilitaires
    public boolean isUsed() {
        return used != null && used;
    }

    public boolean isAvailable() {
        return !isUsed();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/entity/MfaSecret.java

```java
package com.lims.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "mfa_secrets", schema = "lims_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MfaSecret {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "admin_user_id", nullable = false)
    private AdminUser adminUser;

    @Column(name = "secret", nullable = false, length = 512)
    private String secret;

    @Column(name = "active", nullable = false)
    @Builder.Default
    private Boolean active = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "disabled_at")
    private LocalDateTime disabledAt;

    // Méthodes utilitaires
    public boolean isActive() {
        return active != null && active;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/AccountLockedException.java

```java
package com.lims.auth.exception;

import java.time.LocalDateTime;

public class AccountLockedException extends RuntimeException {

    private LocalDateTime lockedUntil;
    private int failedAttempts;

    public AccountLockedException(String message) {
        super(message);
    }

    public AccountLockedException(String message, LocalDateTime lockedUntil) {
        super(message);
        this.lockedUntil = lockedUntil;
    }

    public AccountLockedException(String message, LocalDateTime lockedUntil, int failedAttempts) {
        super(message);
        this.lockedUntil = lockedUntil;
        this.failedAttempts = failedAttempts;
    }

    public AccountLockedException(String message, Throwable cause) {
        super(message, cause);
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/AdminNotFoundException.java

```java
package com.lims.auth.exception;

public class AdminNotFoundException extends RuntimeException {

    private String adminId;
    private String email;

    public AdminNotFoundException(String message) {
        super(message);
    }

    public AdminNotFoundException(String message, String adminId) {
        super(message);
        this.adminId = adminId;
    }

    public AdminNotFoundException(String message, String adminId, String email) {
        super(message);
        this.adminId = adminId;
        this.email = email;
    }

    public AdminNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getAdminId() {
        return adminId;
    }

    public String getEmail() {
        return email;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/AuthenticationException.java

```java
package com.lims.auth.exception;

public class AuthenticationException extends RuntimeException {

    private String errorCode;

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public AuthenticationException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/GlobalExceptionHandler.java

```java
package com.lims.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        log.warn("Erreur d'authentification: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Authentification échouée")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(MfaException.class)
    public ResponseEntity<ErrorResponse> handleMfaException(MfaException ex, WebRequest request) {
        log.warn("Erreur MFA: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Erreur MFA")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<ErrorResponse> handleRateLimitException(RateLimitException ex, WebRequest request) {
        log.warn("Rate limit dépassé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.TOO_MANY_REQUESTS.value())
                .error("Trop de tentatives")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(error);
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ErrorResponse> handleAccountLockedException(AccountLockedException ex, WebRequest request) {
        log.warn("Compte verrouillé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.LOCKED.value())
                .error("Compte verrouillé")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.LOCKED).body(error);
    }

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ErrorResponse> handleTokenException(TokenException ex, WebRequest request) {
        log.warn("Erreur token: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Token invalide")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(KeycloakException.class)
    public ResponseEntity<ErrorResponse> handleKeycloakException(KeycloakException ex, WebRequest request) {
        log.error("Erreur Keycloak: {}", ex.getMessage(), ex);

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Erreur service d'authentification")
                .message("Erreur temporaire du service d'authentification")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    @ExceptionHandler(SessionExpiredException.class)
    public ResponseEntity<ErrorResponse> handleSessionExpiredException(SessionExpiredException ex, WebRequest request) {
        log.info("Session expirée: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Session expirée")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(AdminNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAdminNotFoundException(AdminNotFoundException ex, WebRequest request) {
        log.warn("Administrateur non trouvé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Administrateur non trouvé")
                .message(ex.getMessage())
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Erreur de validation")
                .message("Données invalides")
                .path(request.getDescription(false).replace("uri=", ""))
                .details(errors)
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex, WebRequest request) {
        log.warn("Accès refusé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Accès refusé")
                .message("Vous n'avez pas les permissions nécessaires")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, WebRequest request) {
        log.error("Erreur inattendue: {}", ex.getMessage(), ex);

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Erreur interne")
                .message("Une erreur inattendue s'est produite")
                .path(request.getDescription(false).replace("uri=", ""))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    @lombok.Data
    @lombok.Builder
    public static class ErrorResponse {
        private LocalDateTime timestamp;
        private int status;
        private String error;
        private String message;
        private String path;
        private Map<String, String> details;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/InvalidMfaCodeException.java

```java
package com.lims.auth.exception;

public class InvalidMfaCodeException extends MfaException {

    private int remainingAttempts;
    private boolean isBackupCode;

    public InvalidMfaCodeException(String message) {
        super(message);
    }

    public InvalidMfaCodeException(String message, int remainingAttempts) {
        super(message);
        this.remainingAttempts = remainingAttempts;
    }

    public InvalidMfaCodeException(String message, int remainingAttempts, boolean isBackupCode) {
        super(message);
        this.remainingAttempts = remainingAttempts;
        this.isBackupCode = isBackupCode;
    }

    public InvalidMfaCodeException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getRemainingAttempts() {
        return remainingAttempts;
    }

    public boolean isBackupCode() {
        return isBackupCode;
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/exception/KeycloakException.java

```java
package com.lims.auth.exception;

public class KeycloakException extends RuntimeException {

    private String errorCode;
    private int httpStatus;

    public KeycloakException(String message) {
        super(message);
    }

    public KeycloakException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeycloakException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public KeycloakException(String message, String errorCode, int httpStatus) {
        super(message);
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }

    public KeycloakException(String message, String errorCode, int httpStatus, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/MfaException.java

```java
// MfaException.java
package com.lims.auth.exception;

public class MfaException extends RuntimeException {

    private String errorCode;

    public MfaException(String message) {
        super(message);
    }

    public MfaException(String message, Throwable cause) {
        super(message, cause);
    }

    public MfaException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public MfaException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/exception/RateLimitException.java

```java
package com.lims.auth.exception;

public class RateLimitException extends RuntimeException {

    private int remainingAttempts;
    private long resetTimeMillis;

    public RateLimitException(String message) {
        super(message);
    }

    public RateLimitException(String message, int remainingAttempts, long resetTimeMillis) {
        super(message);
        this.remainingAttempts = remainingAttempts;
        this.resetTimeMillis = resetTimeMillis;
    }

    public RateLimitException(String message, Throwable cause) {
        super(message, cause);
    }

    public int getRemainingAttempts() {
        return remainingAttempts;
    }

    public long getResetTimeMillis() {
        return resetTimeMillis;
    }
}

```

# lims-auth-service/src/main/java/com/lims/auth/exception/SessionExpiredException.java

```java
package com.lims.auth.exception;

import java.time.LocalDateTime;

public class SessionExpiredException extends RuntimeException {

    private String sessionId;
    private LocalDateTime expiredAt;

    public SessionExpiredException(String message) {
        super(message);
    }

    public SessionExpiredException(String message, String sessionId) {
        super(message);
        this.sessionId = sessionId;
    }

    public SessionExpiredException(String message, String sessionId, LocalDateTime expiredAt) {
        super(message);
        this.sessionId = sessionId;
        this.expiredAt = expiredAt;
    }

    public SessionExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getSessionId() {
        return sessionId;
    }

    public LocalDateTime getExpiredAt() {
        return expiredAt;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/exception/TokenException.java

```java
package com.lims.auth.exception;

public class TokenException extends RuntimeException {

    private String tokenType;
    private String errorCode;

    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, String tokenType) {
        super(message);
        this.tokenType = tokenType;
    }

    public TokenException(String message, String tokenType, String errorCode) {
        super(message);
        this.tokenType = tokenType;
        this.errorCode = errorCode;
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/mapper/AdminUserMapper.java

```java
package com.lims.auth.mapper;

import com.lims.auth.config.MapStructConfig;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.entity.AdminUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

@Mapper(config = MapStructConfig.class)
public interface AdminUserMapper {

    @Mapping(target = "fullName", source = ".", qualifiedByName = "mapFullName")
    @Mapping(target = "realm", constant = "lims-admin")
    @Mapping(target = "userType", constant = "ADMIN")
    @Mapping(target = "role", source = "role", qualifiedByName = "mapRole")
    @Mapping(target = "status", source = "status", qualifiedByName = "mapStatus")
    @Mapping(target = "temporarilyLocked", source = ".", qualifiedByName = "mapTemporarilyLocked")
    AdminUserResponse toResponse(AdminUser adminUser);

    @Named("mapFullName")
    default String mapFullName(AdminUser adminUser) {
        if (adminUser.getFirstName() == null && adminUser.getLastName() == null) {
            return null;
        }
        return (adminUser.getFirstName() != null ? adminUser.getFirstName() : "") +
                " " +
                (adminUser.getLastName() != null ? adminUser.getLastName() : "");
    }

    @Named("mapRole")
    default String mapRole(AdminUser.AdminRole role) {
        return role != null ? role.name() : null;
    }

    @Named("mapStatus")
    default String mapStatus(AdminUser.AdminStatus status) {
        return status != null ? status.name() : null;
    }

    @Named("mapTemporarilyLocked")
    default boolean mapTemporarilyLocked(AdminUser adminUser) {
        return adminUser.isTemporarilyLocked();
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/repository/AdminAuditLogRepository.java

```java
package com.lims.auth.repository;

import com.lims.auth.entity.AdminAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AdminAuditLogRepository extends JpaRepository<AdminAuditLog, Long> {

    List<AdminAuditLog> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    Page<AdminAuditLog> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId, Pageable pageable);

    List<AdminAuditLog> findByActionOrderByCreatedAtDesc(String action);

    Page<AdminAuditLog> findByActionOrderByCreatedAtDesc(String action, Pageable pageable);

    List<AdminAuditLog> findByResultOrderByCreatedAtDesc(AdminAuditLog.AuditResult result);

    Page<AdminAuditLog> findByResultOrderByCreatedAtDesc(AdminAuditLog.AuditResult result, Pageable pageable);

    List<AdminAuditLog> findByClientIpOrderByCreatedAtDesc(String clientIp);

    Page<AdminAuditLog> findByClientIpOrderByCreatedAtDesc(String clientIp, Pageable pageable);

    List<AdminAuditLog> findBySessionIdOrderByCreatedAtDesc(String sessionId);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    Page<AdminAuditLog> findByDateRange(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.adminUser.id = :adminUserId AND l.createdAt BETWEEN :startDate AND :endDate ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByAdminUserAndDateRange(@Param("adminUserId") String adminUserId, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.action = :action AND l.result = :result ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findByActionAndResult(@Param("action") String action, @Param("result") AdminAuditLog.AuditResult result);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold ORDER BY l.createdAt DESC")
    List<AdminAuditLog> findRecentFailures(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT l FROM AdminAuditLog l WHERE l.clientIp = :clientIp AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    List<AdminAuditLog> findRecentFailuresByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailures(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.adminUser.id = :adminUserId AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailuresByUser(@Param("adminUserId") String adminUserId, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(l) FROM AdminAuditLog l WHERE l.clientIp = :clientIp AND l.result = 'FAILURE' AND l.createdAt > :threshold")
    long countRecentFailuresByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT l.clientIp, COUNT(l) FROM AdminAuditLog l WHERE l.result = 'FAILURE' AND l.createdAt > :threshold GROUP BY l.clientIp ORDER BY COUNT(l) DESC")
    List<Object[]> findTopFailureIps(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT l.action, COUNT(l) FROM AdminAuditLog l WHERE l.createdAt > :threshold GROUP BY l.action ORDER BY COUNT(l) DESC")
    List<Object[]> findTopActions(@Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBefore(LocalDateTime threshold);
}
```

# lims-auth-service/src/main/java/com/lims/auth/repository/AdminPasswordResetRepository.java

```java
package com.lims.auth.repository;

import com.lims.auth.entity.AdminPasswordReset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminPasswordResetRepository extends JpaRepository<AdminPasswordReset, Long> {

    Optional<AdminPasswordReset> findByTokenAndUsedFalse(String token);

    List<AdminPasswordReset> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.token = :token AND r.used = false AND r.expiresAt > :now")
    Optional<AdminPasswordReset> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.adminUser.id = :adminUserId AND r.used = false AND r.expiresAt > :now")
    List<AdminPasswordReset> findValidTokensForUser(@Param("adminUserId") String adminUserId, @Param("now") LocalDateTime now);

    @Query("SELECT r FROM AdminPasswordReset r WHERE r.expiresAt < :now AND r.used = false")
    List<AdminPasswordReset> findExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE AdminPasswordReset r SET r.used = true, r.usedAt = :usedAt WHERE r.token = :token")
    int markTokenAsUsed(@Param("token") String token, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("UPDATE AdminPasswordReset r SET r.used = true, r.usedAt = :usedAt WHERE r.adminUser.id = :adminUserId AND r.used = false")
    int markAllUserTokensAsUsed(@Param("adminUserId") String adminUserId, @Param("usedAt") LocalDateTime usedAt);

    @Query("SELECT COUNT(r) FROM AdminPasswordReset r WHERE r.adminUser.id = :adminUserId AND r.createdAt > :threshold")
    long countRecentRequestsByUser(@Param("adminUserId") String adminUserId, @Param("threshold") LocalDateTime threshold);

    @Query("SELECT COUNT(r) FROM AdminPasswordReset r WHERE r.clientIp = :clientIp AND r.createdAt > :threshold")
    long countRecentRequestsByIp(@Param("clientIp") String clientIp, @Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBeforeAndUsedTrue(LocalDateTime threshold);

    void deleteByExpiresAtBeforeAndUsedFalse(LocalDateTime threshold);
}
```

# lims-auth-service/src/main/java/com/lims/auth/repository/AdminSessionRepository.java

```java
package com.lims.auth.repository;

import com.lims.auth.entity.AdminSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminSessionRepository extends JpaRepository<AdminSession, String> {

    Optional<AdminSession> findByIdAndActiveTrue(String id);

    Optional<AdminSession> findByIdAndAdminUserIdAndActiveTrue(String id, String adminUserId);

    List<AdminSession> findByAdminUserIdAndActiveTrue(String adminUserId);

    List<AdminSession> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    List<AdminSession> findByClientIpAndActiveTrue(String clientIp);

    @Query("SELECT s FROM AdminSession s WHERE s.adminUser.id = :adminUserId AND s.active = true AND s.expiresAt > :now")
    List<AdminSession> findActiveSessionsForUser(@Param("adminUserId") String adminUserId, @Param("now") LocalDateTime now);

    @Query("SELECT s FROM AdminSession s WHERE s.expiresAt < :now AND s.active = true")
    List<AdminSession> findExpiredActiveSessions(@Param("now") LocalDateTime now);

    @Query("SELECT s FROM AdminSession s WHERE s.lastActivity < :threshold AND s.active = true")
    List<AdminSession> findInactiveSessions(@Param("threshold") LocalDateTime threshold);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.id = :sessionId")
    int deactivateSession(@Param("sessionId") String sessionId, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.adminUser.id = :adminUserId AND s.active = true")
    int deactivateAllUserSessions(@Param("adminUserId") String adminUserId, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.active = false, s.logoutAt = :logoutTime WHERE s.expiresAt < :now AND s.active = true")
    int deactivateExpiredSessions(@Param("now") LocalDateTime now, @Param("logoutTime") LocalDateTime logoutTime);

    @Modifying
    @Query("UPDATE AdminSession s SET s.lastActivity = :now WHERE s.id = :sessionId")
    int updateLastActivity(@Param("sessionId") String sessionId, @Param("now") LocalDateTime now);

    @Query("SELECT COUNT(s) FROM AdminSession s WHERE s.active = true")
    long countActiveSessions();

    @Query("SELECT COUNT(s) FROM AdminSession s WHERE s.adminUser.id = :adminUserId AND s.active = true")
    long countActiveSessionsForUser(@Param("adminUserId") String adminUserId);

    @Query("SELECT COUNT(DISTINCT s.adminUser.id) FROM AdminSession s WHERE s.active = true")
    long countActiveUsers();

    void deleteByAdminUserIdAndActiveFalse(String adminUserId);

    void deleteByCreatedAtBefore(LocalDateTime threshold);
}
```

# lims-auth-service/src/main/java/com/lims/auth/repository/AdminUserRepository.java

```java
// AdminUserRepository.java
package com.lims.auth.repository;

import com.lims.auth.entity.AdminUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminUserRepository extends JpaRepository<AdminUser, String> {

    Optional<AdminUser> findByEmailIgnoreCase(String email);

    Optional<AdminUser> findByKeycloakId(String keycloakId);

    boolean existsByEmailIgnoreCase(String email);

    boolean existsByKeycloakId(String keycloakId);

    List<AdminUser> findByEnabledTrue();

    List<AdminUser> findByEnabledFalse();

    List<AdminUser> findByStatus(AdminUser.AdminStatus status);

    List<AdminUser> findByRole(AdminUser.AdminRole role);

    Page<AdminUser> findByEnabledTrue(Pageable pageable);

    Page<AdminUser> findByStatus(AdminUser.AdminStatus status, Pageable pageable);

    Page<AdminUser> findByRole(AdminUser.AdminRole role, Pageable pageable);

    @Query("SELECT u FROM AdminUser u WHERE u.enabled = true AND u.lockedUntil IS NULL")
    List<AdminUser> findActiveUsers();

    @Query("SELECT u FROM AdminUser u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil > :now")
    List<AdminUser> findLockedUsers(@Param("now") LocalDateTime now);

    @Query("SELECT u FROM AdminUser u WHERE u.failedAttempts >= :maxAttempts")
    List<AdminUser> findUsersWithFailedAttempts(@Param("maxAttempts") int maxAttempts);

    @Query("SELECT u FROM AdminUser u WHERE u.lastLogin < :threshold")
    List<AdminUser> findInactiveUsers(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT u FROM AdminUser u WHERE u.mfaEnabled = false")
    List<AdminUser> findUsersWithoutMfa();

    @Query("SELECT u FROM AdminUser u WHERE u.email LIKE %:search% OR u.firstName LIKE %:search% OR u.lastName LIKE %:search%")
    Page<AdminUser> findBySearchTerm(@Param("search") String search, Pageable pageable);

    @Modifying
    @Query("UPDATE AdminUser u SET u.failedAttempts = 0, u.lockedUntil = NULL WHERE u.id = :userId")
    int resetFailedAttempts(@Param("userId") String userId);

    @Modifying
    @Query("UPDATE AdminUser u SET u.lockedUntil = :lockUntil WHERE u.id = :userId")
    int lockUser(@Param("userId") String userId, @Param("lockUntil") LocalDateTime lockUntil);

    @Modifying
    @Query("UPDATE AdminUser u SET u.enabled = false WHERE u.id = :userId")
    int disableUser(@Param("userId") String userId);

    @Modifying
    @Query("UPDATE AdminUser u SET u.enabled = true WHERE u.id = :userId")
    int enableUser(@Param("userId") String userId);

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.enabled = true")
    long countActiveUsers();

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.role = :role")
    long countByRole(@Param("role") AdminUser.AdminRole role);

    @Query("SELECT COUNT(u) FROM AdminUser u WHERE u.mfaEnabled = true")
    long countUsersWithMfa();
}
```

# lims-auth-service/src/main/java/com/lims/auth/repository/MfaBackupCodeRepository.java

```java
package com.lims.auth.repository;

import com.lims.auth.entity.MfaBackupCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MfaBackupCodeRepository extends JpaRepository<MfaBackupCode, Long> {

    List<MfaBackupCode> findByAdminUserIdAndUsedFalse(String adminUserId);

    List<MfaBackupCode> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    Optional<MfaBackupCode> findByAdminUserIdAndCodeAndUsedFalse(String adminUserId, String code);

    boolean existsByAdminUserIdAndCodeAndUsedFalse(String adminUserId, String code);

    @Query("SELECT COUNT(c) FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = false")
    long countByAdminUserIdAndUsedFalse(@Param("adminUserId") String adminUserId);

    @Query("SELECT COUNT(c) FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = true")
    long countByAdminUserIdAndUsedTrue(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("UPDATE MfaBackupCode c SET c.used = true, c.usedAt = :usedAt WHERE c.id = :codeId")
    int markCodeAsUsed(@Param("codeId") Long codeId, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("UPDATE MfaBackupCode c SET c.used = true, c.usedAt = :usedAt WHERE c.adminUser.id = :adminUserId AND c.code = :code AND c.used = false")
    int markCodeAsUsedByUserAndCode(@Param("adminUserId") String adminUserId, @Param("code") String code, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("DELETE FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId")
    int deleteByAdminUserId(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("DELETE FROM MfaBackupCode c WHERE c.adminUser.id = :adminUserId AND c.used = true")
    int deleteUsedCodesByAdminUserId(@Param("adminUserId") String adminUserId);

    @Query("SELECT c FROM MfaBackupCode c WHERE c.usedAt < :threshold AND c.used = true")
    List<MfaBackupCode> findOldUsedCodes(@Param("threshold") LocalDateTime threshold);

    void deleteByCreatedAtBeforeAndUsedTrue(LocalDateTime threshold);
}

```

# lims-auth-service/src/main/java/com/lims/auth/repository/MfaSecretRepository.java

```java
package com.lims.auth.repository;

import com.lims.auth.entity.MfaSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface MfaSecretRepository extends JpaRepository<MfaSecret, Long> {

    Optional<MfaSecret> findByAdminUserIdAndActiveTrue(String adminUserId);

    List<MfaSecret> findByAdminUserIdOrderByCreatedAtDesc(String adminUserId);

    boolean existsByAdminUserIdAndActiveTrue(String adminUserId);

    @Query("SELECT s FROM MfaSecret s WHERE s.adminUser.id = :adminUserId AND s.active = true")
    Optional<MfaSecret> findActiveSecretForUser(@Param("adminUserId") String adminUserId);

    @Modifying
    @Query("UPDATE MfaSecret s SET s.active = false, s.disabledAt = :disabledAt WHERE s.adminUser.id = :adminUserId AND s.active = true")
    int deactivateUserSecrets(@Param("adminUserId") String adminUserId, @Param("disabledAt") LocalDateTime disabledAt);

    @Modifying
    @Query("UPDATE MfaSecret s SET s.active = false, s.disabledAt = :disabledAt WHERE s.id = :secretId")
    int deactivateSecret(@Param("secretId") Long secretId, @Param("disabledAt") LocalDateTime disabledAt);

    @Query("SELECT COUNT(s) FROM MfaSecret s WHERE s.active = true")
    long countActiveSecrets();

    @Query("SELECT COUNT(DISTINCT s.adminUser.id) FROM MfaSecret s WHERE s.active = true")
    long countUsersWithMfa();

    void deleteByAdminUserIdAndActiveFalse(String adminUserId);

    void deleteByCreatedAtBeforeAndActiveFalse(LocalDateTime threshold);
}

```

# lims-auth-service/src/main/java/com/lims/auth/security/AdminSecurityAnnotations.java

```java
package com.lims.auth.security;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

/**
 * Annotations de sécurité personnalisées pour les administrateurs LIMS
 */
public class AdminSecurityAnnotations {

    /**
     * Nécessite les permissions de super administrateur
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public @interface RequireSuperAdmin {
    }

    /**
     * Nécessite les permissions d'administrateur système
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole('SYSTEM_ADMIN') or hasRole('SUPER_ADMIN')")
    public @interface RequireSystemAdmin {
    }

    /**
     * Nécessite les permissions de gestion des utilisateurs
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('USER_MANAGEMENT') or hasRole('SUPER_ADMIN')")
    public @interface RequireUserManagement {
    }

    /**
     * Nécessite les permissions de lecture des audits
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('AUDIT_READ') or hasRole('SUPER_ADMIN')")
    public @interface RequireAuditRead {
    }

    /**
     * Nécessite les permissions de modification de la configuration
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority('CONFIGURATION_WRITE') or hasRole('SUPER_ADMIN')")
    public @interface RequireConfigurationWrite {
    }

    /**
     * Nécessite que le MFA soit vérifié
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("@adminSecurityContext.getCurrentContext() != null and @adminSecurityContext.getCurrentContext().isMfaVerified()")
    public @interface RequireMfaVerified {
    }

    /**
     * Nécessite une permission spécifique
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasAuthority(#permission) or hasRole('SUPER_ADMIN')")
    public @interface RequirePermission {
        String value();
    }

    /**
     * Nécessite un rôle spécifique
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("hasRole(#role)")
    public @interface RequireRole {
        String value();
    }

    /**
     * Nécessite que l'utilisateur soit authentifié et du bon realm
     */
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @PreAuthorize("isAuthenticated() and @adminSecurityContext.getCurrentContext() != null and @adminSecurityContext.getCurrentContext().isValidRealm()")
    public @interface RequireAdminRealm {
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/security/AdminSecurityContext.java

```java
package com.lims.auth.security;

import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Contexte de sécurité pour les administrateurs LIMS
 * Fournit des méthodes utilitaires pour accéder aux informations de l'administrateur connecté
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminSecurityContext {

    private String adminId;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private String realm;
    private String userType;
    private List<String> permissions;
    private String sessionId;
    private boolean mfaVerified;
    private LocalDateTime tokenIssuedAt;
    private LocalDateTime tokenExpiresAt;

    /**
     * Récupère le contexte de sécurité de l'administrateur actuellement connecté
     */
    public static AdminSecurityContext getCurrentContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return fromJwt(jwt);
        }

        return null;
    }

    /**
     * Crée un contexte de sécurité à partir d'un JWT
     */
    public static AdminSecurityContext fromJwt(Jwt jwt) {
        return AdminSecurityContext.builder()
                .adminId(jwt.getSubject())
                .email(jwt.getClaimAsString("email"))
                .firstName(jwt.getClaimAsString("first_name"))
                .lastName(jwt.getClaimAsString("last_name"))
                .role(jwt.getClaimAsString("role"))
                .realm(jwt.getClaimAsString("realm"))
                .userType(jwt.getClaimAsString("user_type"))
                .permissions(jwt.getClaimAsStringList("permissions"))
                .sessionId(jwt.getClaimAsString("session_id"))
                .mfaVerified(jwt.getClaimAsBoolean("mfa_verified"))
                .tokenIssuedAt(jwt.getIssuedAt() != null ?
                        LocalDateTime.ofInstant(jwt.getIssuedAt(), java.time.ZoneId.systemDefault()) : null)
                .tokenExpiresAt(jwt.getExpiresAt() != null ?
                        LocalDateTime.ofInstant(jwt.getExpiresAt(), java.time.ZoneId.systemDefault()) : null)
                .build();
    }

    /**
     * Vérifie si l'administrateur a une permission spécifique
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Vérifie si l'administrateur a l'un des rôles spécifiés
     */
    public boolean hasRole(String... roles) {
        if (role == null) return false;

        for (String r : roles) {
            if (role.equalsIgnoreCase(r)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si l'administrateur est un super administrateur
     */
    public boolean isSuperAdmin() {
        return hasRole("SUPER_ADMIN");
    }

    /**
     * Vérifie si l'administrateur est un administrateur système
     */
    public boolean isSystemAdmin() {
        return hasRole("SYSTEM_ADMIN", "SUPER_ADMIN");
    }

    /**
     * Vérifie si l'administrateur peut gérer les utilisateurs
     */
    public boolean canManageUsers() {
        return hasPermission("USER_MANAGEMENT") || isSuperAdmin();
    }

    /**
     * Vérifie si l'administrateur peut lire les audits
     */
    public boolean canReadAudits() {
        return hasPermission("AUDIT_READ") || isSuperAdmin();
    }

    /**
     * Vérifie si l'administrateur peut modifier la configuration
     */
    public boolean canWriteConfiguration() {
        return hasPermission("CONFIGURATION_WRITE") || isSuperAdmin();
    }

    /**
     * Récupère le nom complet de l'administrateur
     */
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        } else {
            return email;
        }
    }

    /**
     * Vérifie si le token est encore valide
     */
    public boolean isTokenValid() {
        return tokenExpiresAt != null && tokenExpiresAt.isAfter(LocalDateTime.now());
    }

    /**
     * Vérifie si le MFA est vérifié
     */
    public boolean isMfaVerified() {
        return mfaVerified;
    }

    /**
     * Vérifie si l'administrateur appartient au bon realm
     */
    public boolean isValidRealm() {
        return "lims-admin".equals(realm);
    }

    /**
     * Vérifie si l'administrateur est du bon type
     */
    public boolean isValidUserType() {
        return "ADMIN".equals(userType);
    }

    /**
     * Validation complète du contexte de sécurité
     */
    public boolean isValid() {
        return adminId != null &&
                email != null &&
                isValidRealm() &&
                isValidUserType() &&
                isMfaVerified() &&
                isTokenValid();
    }

    /**
     * Méthodes utilitaires statiques
     */
    public static String getCurrentAdminId() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getAdminId() : null;
    }

    public static String getCurrentAdminEmail() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getEmail() : null;
    }

    public static String getCurrentSessionId() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getSessionId() : null;
    }

    public static List<String> getCurrentPermissions() {
        AdminSecurityContext context = getCurrentContext();
        return context != null ? context.getPermissions() : List.of();
    }

    public static boolean currentUserHasPermission(String permission) {
        AdminSecurityContext context = getCurrentContext();
        return context != null && context.hasPermission(permission);
    }

    public static boolean currentUserHasRole(String... roles) {
        AdminSecurityContext context = getCurrentContext();
        return context != null && context.hasRole(roles);
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/service/AdminAuthenticationService.java

```java
package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.dto.request.AdminLoginRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.entity.AdminSession;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.entity.MfaSecret;
import com.lims.auth.exception.AccountLockedException;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.RateLimitException;
import com.lims.auth.mapper.AdminUserMapper;
import com.lims.auth.repository.AdminSessionRepository;
import com.lims.auth.repository.AdminUserRepository;
import com.lims.auth.repository.MfaSecretRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminAuthenticationService {

    private final AdminUserRepository adminUserRepository;
    private final AdminSessionRepository adminSessionRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final AdminMfaService adminMfaService;
    private final AdminTokenService adminTokenService;
    private final RateLimitService rateLimitService;
    private final AdminUserMapper adminUserMapper;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;
    private final KeycloakAdminService keycloakAdminService;

    private static final String RATE_LIMIT_PREFIX = "auth:rate_limit:";
    private static final String FAILED_ATTEMPTS_PREFIX = "auth:failed_attempts:";
    private static final String LOCKOUT_PREFIX = "auth:lockout:";

    @Transactional
    public AdminLoginResponse authenticate(AdminLoginRequest request, String clientIp, String userAgent) {

        // 1. Vérifier le rate limiting
        checkRateLimit(request.getEmail(), clientIp);

        // 2. Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> new AuthenticationException("Identifiants invalides"));

        // 3. Vérifier le statut du compte
        validateAccountStatus(adminUser);

        // 4. Vérifier les tentatives échouées
        checkFailedAttempts(adminUser);

        try {
            // 5. Authentification via Keycloak
            String keycloakToken = keycloakAdminService.authenticate(request.getEmail(), request.getPassword());

            // 6. Vérifier si MFA est configuré
            Optional<MfaSecret> mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminUser.getId());

            if (mfaSecret.isEmpty()) {
                // Premier login - Setup MFA requis
                String setupToken = generateMfaSetupToken(adminUser);

                log.info("Premier login détecté pour admin: {} - Setup MFA requis", request.getEmail());
                return AdminLoginResponse.mfaSetupRequired(setupToken);
            }

            // 7. Vérifier le code OTP si fourni
            if (request.getOtpCode() != null && !request.getOtpCode().trim().isEmpty()) {
                boolean otpValid = adminMfaService.validateOtpCode(
                        adminUser.getId(),
                        request.getOtpCode().trim()
                );

                if (!otpValid) {
                    incrementFailedAttempts(adminUser);
                    throw new AuthenticationException("Code OTP invalide");
                }

                // 8. Connexion réussie - Génération des tokens
                return completeAuthentication(adminUser, clientIp, userAgent, keycloakToken);

            } else {
                // Code OTP manquant
                throw new AuthenticationException("Code OTP requis");
            }

        } catch (Exception e) {
            // Incrémenter les tentatives échouées
            incrementFailedAttempts(adminUser);

            // Enregistrer la tentative dans les logs d'audit
            logFailedAttempt(adminUser, clientIp, userAgent, e.getMessage());

            if (e instanceof AuthenticationException) {
                throw e;
            }

            throw new AuthenticationException("Erreur lors de l'authentification");
        }
    }

    private void validateLocalPassword(AdminUser adminUser, String password) {
        // En mode de développement ou si pas de mot de passe hashé, utiliser un mot de passe par défaut
        String storedPassword = adminUser.getKeycloakId(); // Utiliser keycloakId comme stockage temporaire
        if (storedPassword == null || storedPassword.isEmpty()) {
            // Mot de passe par défaut pour le développement
            if (!"dev_password_123".equals(password)) {
                throw new AuthenticationException("Identifiants invalides");
            }
        } else {
            // Vérifier le mot de passe hashé
            if (!passwordEncoder.matches(password, storedPassword)) {
                throw new AuthenticationException("Identifiants invalides");
            }
        }
    }

    private void checkRateLimit(String email, String clientIp) {
        String emailKey = RATE_LIMIT_PREFIX + "email:" + email;
        String ipKey = RATE_LIMIT_PREFIX + "ip:" + clientIp;

        // Vérifier rate limiting par email
        Integer emailAttempts = (Integer) redisTemplate.opsForValue().get(emailKey);
        if (emailAttempts != null && emailAttempts >= authProperties.getRateLimit().getMaxAttempts()) {
            log.warn("Rate limit dépassé pour email: {}", email);
            throw new RateLimitException("Trop de tentatives de connexion pour cet email");
        }

        // Vérifier rate limiting par IP
        Integer ipAttempts = (Integer) redisTemplate.opsForValue().get(ipKey);
        if (ipAttempts != null && ipAttempts >= authProperties.getRateLimit().getMaxAttempts()) {
            log.warn("Rate limit dépassé pour IP: {}", clientIp);
            throw new RateLimitException("Trop de tentatives de connexion depuis cette adresse IP");
        }

        // Incrémenter les compteurs
        redisTemplate.opsForValue().increment(emailKey);
        redisTemplate.expire(emailKey, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);

        redisTemplate.opsForValue().increment(ipKey);
        redisTemplate.expire(ipKey, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
    }

    private void validateAccountStatus(AdminUser adminUser) {
        if (!adminUser.isEnabled()) {
            throw new AuthenticationException("Compte désactivé");
        }

        if (adminUser.getLockedUntil() != null && adminUser.getLockedUntil().isAfter(LocalDateTime.now())) {
            throw new AccountLockedException("Compte temporairement verrouillé jusqu'à " + adminUser.getLockedUntil());
        }
    }

    private void checkFailedAttempts(AdminUser adminUser) {
        if (adminUser.getFailedAttempts() >= authProperties.getSecurity().getMaxFailedAttempts()) {
            // Verrouiller le compte temporairement
            LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(authProperties.getSecurity().getLockoutDurationMinutes());
            adminUser.setLockedUntil(lockUntil);
            adminUser.setFailedAttempts(0);
            adminUserRepository.save(adminUser);

            throw new AccountLockedException("Compte verrouillé temporairement suite à trop de tentatives échouées");
        }
    }

    private String generateMfaSetupToken(AdminUser adminUser) {
        String setupToken = UUID.randomUUID().toString();

        // Stocker le token temporairement dans Redis
        String key = "mfa_setup_token:" + setupToken;
        redisTemplate.opsForValue().set(key, adminUser.getId(), authProperties.getMfa().getSetupTokenExpiry(), TimeUnit.SECONDS);

        return setupToken;
    }

    private void incrementFailedAttempts(AdminUser adminUser) {
        adminUser.setFailedAttempts(adminUser.getFailedAttempts() + 1);
        adminUserRepository.save(adminUser);

        log.warn("Tentative de connexion échouée pour admin: {} - Tentatives: {}",
                adminUser.getEmail(), adminUser.getFailedAttempts());
    }

    private AdminLoginResponse completeAuthentication(AdminUser adminUser, String clientIp,
                                                      String userAgent, String keycloakToken) {

        // Réinitialiser les tentatives échouées
        adminUser.setFailedAttempts(0);
        adminUser.setLockedUntil(null);
        adminUser.setLastLogin(LocalDateTime.now());
        adminUser.setLastLoginIp(clientIp);
        adminUserRepository.save(adminUser);

        // Créer une nouvelle session
        AdminSession session = createAdminSession(adminUser, clientIp, userAgent);

        // Générer les tokens JWT
        String accessToken = adminTokenService.generateAccessToken(adminUser, session);
        String refreshToken = adminTokenService.generateRefreshToken(adminUser, session);

        // Construire la réponse
        AdminLoginResponse.AdminUserInfo userInfo = AdminLoginResponse.AdminUserInfo.builder()
                .id(adminUser.getId())
                .email(adminUser.getEmail())
                .firstName(adminUser.getFirstName())
                .lastName(adminUser.getLastName())
                .role(adminUser.getRole().name())
                .realm("lims-admin")
                .userType("ADMIN")
                .permissions(adminUser.getPermissions())
                .mfaEnabled(true)
                .lastLogin(adminUser.getLastLogin())
                .status(adminUser.getStatus().name())
                .build();

        log.info("Connexion admin réussie - Email: {}, SessionId: {}, Mode: Keycloak",
                adminUser.getEmail(), session.getId());

        return AdminLoginResponse.success(accessToken, refreshToken, session.getId(), userInfo);
    }

    private AdminSession createAdminSession(AdminUser adminUser, String clientIp, String userAgent) {
        AdminSession session = AdminSession.builder()
                .id(UUID.randomUUID().toString())
                .adminUser(adminUser)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .createdAt(LocalDateTime.now())
                .lastActivity(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(authProperties.getSession().getTimeout()))
                .active(true)
                .build();

        return adminSessionRepository.save(session);
    }

    public AdminUserResponse getCurrentAdmin(String adminId) {
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Administrateur non trouvé"));

        return adminUserMapper.toResponse(adminUser);
    }

    public Map<String, Object> getAdminPermissions(String adminId) {
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Administrateur non trouvé"));

        return Map.of(
                "permissions", adminUser.getPermissions(),
                "role", adminUser.getRole().name(),
                "realm", "lims-admin",
                "keycloakEnabled", keycloakAdminService != null
        );
    }

    @Transactional
    public void logout(String adminId, String sessionId, String clientIp) {
        // Invalider la session
        adminSessionRepository.findByIdAndAdminUserIdAndActiveTrue(sessionId, adminId)
                .ifPresent(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    adminSessionRepository.save(session);
                });

        // Invalider les tokens dans Redis
        adminTokenService.invalidateTokens(adminId, sessionId);

        log.info("Déconnexion admin - AdminId: {}, SessionId: {}, IP: {}", adminId, sessionId, clientIp);
    }

    /**
     * Méthode pour créer un utilisateur admin de développement
     */
    @Transactional
    public AdminUser createDevelopmentAdmin(String email, String firstName, String lastName) {
        if (adminUserRepository.existsByEmailIgnoreCase(email)) {
            return adminUserRepository.findByEmailIgnoreCase(email).orElseThrow();
        }

        AdminUser adminUser = AdminUser.builder()
                .id(UUID.randomUUID().toString())
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .role(AdminUser.AdminRole.SUPER_ADMIN)
                .permissions(java.util.List.of("SYSTEM_ADMIN", "USER_MANAGEMENT", "AUDIT_READ"))
                .enabled(true)
                .status(AdminUser.AdminStatus.ACTIVE)
                .mfaEnabled(false)
                .failedAttempts(0)
                .createdBy("system")
                .createdAt(LocalDateTime.now())
                .build();

        adminUser = adminUserRepository.save(adminUser);

        log.info("Utilisateur admin de développement créé: {}", email);
        return adminUser;
    }

    private void logFailedAttempt(AdminUser adminUser, String clientIp, String userAgent, String reason) {
        log.warn("Tentative de connexion échouée - Email: {}, IP: {}, UserAgent: {}, Raison: {}",
                adminUser.getEmail(), clientIp, userAgent, reason);

        // Ici on pourrait envoyer un événement à un système d'audit
        // ou enregistrer dans une table d'audit dédiée
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/service/AdminMfaService.java

```java
package com.lims.auth.service;

import com.lims.auth.dto.request.AdminMfaVerifyRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminMfaSetupResponse;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.entity.MfaSecret;
import com.lims.auth.entity.MfaBackupCode;
import com.lims.auth.repository.AdminUserRepository;
import com.lims.auth.repository.MfaSecretRepository;
import com.lims.auth.repository.MfaBackupCodeRepository;
import com.lims.auth.exception.MfaException;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.config.LimsAuthProperties;

import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminMfaService {

    private final AdminUserRepository adminUserRepository;
    private final MfaSecretRepository mfaSecretRepository;
    private final MfaBackupCodeRepository mfaBackupCodeRepository;
    private final AdminTokenService adminTokenService;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;
    private final SecretGenerator secretGenerator;

    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

    private static final String MFA_SETUP_TOKEN_PREFIX = "mfa_setup_token:";
    private static final String MFA_TEMP_SECRET_PREFIX = "mfa_temp_secret:";
    private static final String QR_CODE_SIZE = "200x200";
    private static final int QR_CODE_MARGIN = 1;

    @Transactional
    public AdminMfaSetupResponse generateMfaSetup(String setupToken) {

        // Récupérer l'ID admin depuis Redis
        String adminId = (String) redisTemplate.opsForValue().get(MFA_SETUP_TOKEN_PREFIX + setupToken);
        if (adminId == null) {
            throw new MfaException("Token de setup invalide ou expiré");
        }

        // Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new MfaException("Utilisateur non trouvé"));

        // Vérifier qu'il n'y a pas déjà un MFA configuré
        Optional<MfaSecret> existingSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId);
        if (existingSecret.isPresent()) {
            throw new MfaException("MFA déjà configuré pour cet utilisateur");
        }

        try {
            // Générer le secret TOTP
            String secret = secretGenerator.generate();

            // Stocker temporairement le secret (10 minutes)
            String tempSecretKey = MFA_TEMP_SECRET_PREFIX + setupToken;
            redisTemplate.opsForValue().set(tempSecretKey, secret, 10, TimeUnit.MINUTES);

            // Générer l'URL et le QR Code
            String qrCodeUrl = generateQrCodeUrl(adminUser.getEmail(), secret);
            String qrCodeImage = generateQrCodeImage(qrCodeUrl);

            log.info("QR Code MFA généré pour admin: {}", adminUser.getEmail());

            return AdminMfaSetupResponse.success(
                    qrCodeImage,
                    qrCodeUrl,
                    secret, // Ne pas exposer en production
                    authProperties.getMfa().getIssuer()
            );

        } catch (Exception e) {
            log.error("Erreur génération QR Code MFA pour admin: {}", adminUser.getEmail(), e);
            throw new MfaException("Erreur lors de la génération du QR Code");
        }
    }

    @Transactional
    public AdminLoginResponse verifyMfaSetup(AdminMfaVerifyRequest request, String clientIp, String userAgent) {

        // Récupérer l'ID admin depuis Redis
        String adminId = (String) redisTemplate.opsForValue().get(MFA_SETUP_TOKEN_PREFIX + request.getSetupToken());
        if (adminId == null) {
            throw new MfaException("Token de setup invalide ou expiré");
        }

        // Récupérer le secret temporaire
        String tempSecretKey = MFA_TEMP_SECRET_PREFIX + request.getSetupToken();
        String secret = (String) redisTemplate.opsForValue().get(tempSecretKey);
        if (secret == null) {
            throw new MfaException("Secret temporaire non trouvé ou expiré");
        }

        // Récupérer l'utilisateur
        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new MfaException("Utilisateur non trouvé"));

        // Vérifier le code OTP
        if (!codeVerifier.isValidCode(secret, request.getOtpCode())) {
            log.warn("Code OTP invalide lors du setup MFA pour admin: {}", adminUser.getEmail());
            throw new MfaException("Code OTP invalide");
        }

        try {
            // Sauvegarder le secret MFA définitivement
            MfaSecret mfaSecret = MfaSecret.builder()
                    .adminUser(adminUser)
                    .secret(secret)
                    .active(true)
                    .createdAt(LocalDateTime.now())
                    .build();
            mfaSecretRepository.save(mfaSecret);

            // Générer les codes de récupération
            List<String> backupCodes = generateBackupCodes(adminUser);

            // Nettoyer les données temporaires
            redisTemplate.delete(MFA_SETUP_TOKEN_PREFIX + request.getSetupToken());
            redisTemplate.delete(tempSecretKey);

            // Mettre à jour le statut utilisateur
            adminUser.setMfaEnabled(true);
            adminUser.setMfaSetupAt(LocalDateTime.now());
            adminUserRepository.save(adminUser);

            // Créer la session et connecter automatiquement
            return completeAuthenticationAfterMfaSetup(adminUser, clientIp, userAgent, backupCodes);

        } catch (Exception e) {
            log.error("Erreur finalisation setup MFA pour admin: {}", adminUser.getEmail(), e);
            throw new MfaException("Erreur lors de la finalisation du setup MFA");
        }
    }

    public boolean validateOtpCode(String adminId, String otpCode) {

        // Récupérer le secret MFA
        MfaSecret mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId)
                .orElseThrow(() -> new MfaException("MFA non configuré"));

        // Vérifier le code OTP
        boolean isValid = codeVerifier.isValidCode(mfaSecret.getSecret(), otpCode);

        if (!isValid) {
            log.warn("Code OTP invalide pour admin: {}", adminId);

            // Vérifier si c'est un code de récupération
            return validateBackupCode(adminId, otpCode);
        }

        return true;
    }

    private boolean validateBackupCode(String adminId, String backupCode) {

        Optional<MfaBackupCode> backupCodeEntity = mfaBackupCodeRepository
                .findByAdminUserIdAndCodeAndUsedFalse(adminId, backupCode);

        if (backupCodeEntity.isPresent()) {
            // Marquer le code comme utilisé
            MfaBackupCode code = backupCodeEntity.get();
            code.setUsed(true);
            code.setUsedAt(LocalDateTime.now());
            mfaBackupCodeRepository.save(code);

            log.info("Code de récupération MFA utilisé pour admin: {}", adminId);
            return true;
        }

        return false;
    }

    private List<String> generateBackupCodes(AdminUser adminUser) {

        // Supprimer les anciens codes
        mfaBackupCodeRepository.deleteByAdminUserId(adminUser.getId());

        List<String> backupCodes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < authProperties.getMfa().getBackupCodes().getCount(); i++) {
            String code = generateBackupCode(random);
            backupCodes.add(code);

            MfaBackupCode backupCodeEntity = MfaBackupCode.builder()
                    .adminUser(adminUser)
                    .code(code)
                    .used(false)
                    .createdAt(LocalDateTime.now())
                    .build();

            mfaBackupCodeRepository.save(backupCodeEntity);
        }

        log.info("Codes de récupération MFA générés pour admin: {} - Nombre: {}",
                adminUser.getEmail(), backupCodes.size());

        return backupCodes;
    }

    private String generateBackupCode(SecureRandom random) {
        StringBuilder code = new StringBuilder();
        int length = authProperties.getMfa().getBackupCodes().getLength();

        for (int i = 0; i < length; i++) {
            code.append(random.nextInt(10));
        }

        return code.toString();
    }

    private String generateQrCodeUrl(String email, String secret) {
        String issuer = authProperties.getMfa().getIssuer();
        String accountName = email;

        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                URLEncoder.encode(issuer, StandardCharsets.UTF_8),
                URLEncoder.encode(accountName, StandardCharsets.UTF_8),
                secret,
                URLEncoder.encode(issuer, StandardCharsets.UTF_8)
        );
    }

    private String generateQrCodeImage(String qrCodeUrl) throws WriterException, IOException {

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, QR_CODE_MARGIN);

        BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUrl, BarcodeFormat.QR_CODE, 200, 200, hints);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        byte[] qrCodeBytes = outputStream.toByteArray();
        return Base64.getEncoder().encodeToString(qrCodeBytes);
    }

    private AdminLoginResponse completeAuthenticationAfterMfaSetup(AdminUser adminUser, String clientIp,
                                                                   String userAgent, List<String> backupCodes) {

        // Créer une session temporaire pour finaliser l'authentification
        // Cette logique devrait être similaire à celle du service d'authentification

        // Mettre à jour les informations de connexion
        adminUser.setLastLogin(LocalDateTime.now());
        adminUser.setLastLoginIp(clientIp);
        adminUserRepository.save(adminUser);

        // Créer une session
        String sessionId = UUID.randomUUID().toString();

        // Générer les tokens
        String accessToken = adminTokenService.generateAccessToken(adminUser, sessionId);
        String refreshToken = adminTokenService.generateRefreshToken(adminUser, sessionId);

        // Construire la réponse
        AdminLoginResponse.AdminUserInfo userInfo = AdminLoginResponse.AdminUserInfo.builder()
                .id(adminUser.getId())
                .email(adminUser.getEmail())
                .firstName(adminUser.getFirstName())
                .lastName(adminUser.getLastName())
                .role(adminUser.getRole().name())
                .realm("lims-admin")
                .userType("ADMIN")
                .permissions(adminUser.getPermissions())
                .mfaEnabled(true)
                .lastLogin(adminUser.getLastLogin())
                .status(adminUser.getStatus().name())
                .build();

        AdminLoginResponse response = AdminLoginResponse.success(accessToken, refreshToken, sessionId, userInfo);
        response.setBackupCodes(backupCodes);

        log.info("Setup MFA complété et connexion automatique pour admin: {}", adminUser.getEmail());

        return response;
    }

    public List<String> getBackupCodes(String adminId) {
        return mfaBackupCodeRepository.findByAdminUserIdAndUsedFalse(adminId)
                .stream()
                .map(MfaBackupCode::getCode)
                .collect(Collectors.toList());
    }

    @Transactional
    public List<String> regenerateBackupCodes(String adminId, String otpCode) {

        // Vérifier le code OTP avant de régénérer
        if (!validateOtpCode(adminId, otpCode)) {
            throw new MfaException("Code OTP invalide");
        }

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        // Générer de nouveaux codes
        List<String> newBackupCodes = generateBackupCodes(adminUser);

        log.info("Codes de récupération MFA régénérés pour admin: {}", adminUser.getEmail());

        return newBackupCodes;
    }

    public Map<String, Object> getMfaStatus(String adminId) {

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        Optional<MfaSecret> mfaSecret = mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId);

        if (mfaSecret.isEmpty()) {
            return Map.of(
                    "mfaEnabled", false,
                    "setupRequired", true
            );
        }

        long remainingBackupCodes = mfaBackupCodeRepository.countByAdminUserIdAndUsedFalse(adminId);

        return Map.of(
                "mfaEnabled", true,
                "setupRequired", false,
                "setupDate", mfaSecret.get().getCreatedAt(),
                "remainingBackupCodes", remainingBackupCodes
        );
    }

    @Transactional
    public void disableMfa(String adminId, String otpCode) {

        // Vérifier le code OTP avant de désactiver
        if (!validateOtpCode(adminId, otpCode)) {
            throw new MfaException("Code OTP invalide");
        }

        AdminUser adminUser = adminUserRepository.findById(adminId)
                .orElseThrow(() -> new AuthenticationException("Utilisateur non trouvé"));

        // Désactiver le secret MFA
        mfaSecretRepository.findByAdminUserIdAndActiveTrue(adminId)
                .ifPresent(secret -> {
                    secret.setActive(false);
                    secret.setDisabledAt(LocalDateTime.now());
                    mfaSecretRepository.save(secret);
                });

        // Supprimer les codes de récupération
        mfaBackupCodeRepository.deleteByAdminUserId(adminId);

        // Mettre à jour le statut utilisateur
        adminUser.setMfaEnabled(false);
        adminUser.setMfaSetupAt(null);
        adminUserRepository.save(adminUser);

        log.info("MFA désactivé pour admin: {}", adminUser.getEmail());
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/service/AdminTokenService.java

```java
package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.dto.response.AdminTokenResponse;
import com.lims.auth.entity.AdminSession;
import com.lims.auth.entity.AdminUser;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.repository.AdminSessionRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminTokenService {

    private final AdminSessionRepository adminSessionRepository;
    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;

    @Value("${lims.auth.jwt.secret:default-secret-key-for-development-only-change-in-production}")
    private String jwtSecret;

    @Value("${lims.auth.jwt.access-token-validity:3600}")
    private int accessTokenValiditySeconds;

    @Value("${lims.auth.jwt.refresh-token-validity:86400}")
    private int refreshTokenValiditySeconds;

    private static final String TOKEN_PREFIX = "admin_token:";
    private static final String REFRESH_TOKEN_PREFIX = "admin_refresh:";
    private static final String SESSION_PREFIX = "admin_session:";
    private static final String BLACKLIST_PREFIX = "admin_blacklist:";

    public String generateAccessToken(AdminUser adminUser, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenValiditySeconds * 1000L);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", adminUser.getId());
        claims.put("email", adminUser.getEmail());
        claims.put("realm", "lims-admin");
        claims.put("user_type", "ADMIN");
        claims.put("role", adminUser.getRole().name());
        claims.put("permissions", adminUser.getPermissions());
        claims.put("session_id", sessionId);
        claims.put("mfa_verified", true);
        claims.put("iat", now.getTime() / 1000);
        claims.put("exp", expiryDate.getTime() / 1000);

        String token = Jwts.builder()
                .claims(claims)
                .issuer("lims-auth-service")
                .subject(adminUser.getId())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        // Stocker le token dans Redis pour validation
        String tokenKey = TOKEN_PREFIX + adminUser.getId() + ":" + sessionId;
        redisTemplate.opsForValue().set(tokenKey, token, accessTokenValiditySeconds, TimeUnit.SECONDS);

        log.debug("Token d'accès généré pour admin: {} - Session: {}", adminUser.getEmail(), sessionId);

        return token;
    }

    public String generateAccessToken(AdminUser adminUser, AdminSession session) {
        return generateAccessToken(adminUser, session.getId());
    }

    public String generateRefreshToken(AdminUser adminUser, String sessionId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenValiditySeconds * 1000L);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", adminUser.getId());
        claims.put("email", adminUser.getEmail());
        claims.put("session_id", sessionId);
        claims.put("type", "refresh");
        claims.put("iat", now.getTime() / 1000);
        claims.put("exp", expiryDate.getTime() / 1000);

        String refreshToken = Jwts.builder()
                .claims(claims)
                .issuer("lims-auth-service")
                .subject(adminUser.getId())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS512)
                .compact();

        // Stocker le refresh token dans Redis
        String refreshKey = REFRESH_TOKEN_PREFIX + adminUser.getId() + ":" + sessionId;
        redisTemplate.opsForValue().set(refreshKey, refreshToken, refreshTokenValiditySeconds, TimeUnit.SECONDS);

        log.debug("Token de rafraîchissement généré pour admin: {} - Session: {}", adminUser.getEmail(), sessionId);

        return refreshToken;
    }

    public String generateRefreshToken(AdminUser adminUser, AdminSession session) {
        return generateRefreshToken(adminUser, session.getId());
    }

    public AdminTokenResponse refreshToken(String refreshToken, String clientIp) {
        try {
            // Vérifier si le token est en blacklist
            if (isTokenBlacklisted(refreshToken)) {
                throw new AuthenticationException("Token révoqué");
            }

            // Décoder et valider le refresh token
            Claims claims = validateAndParseToken(refreshToken);

            String adminId = claims.getSubject();
            String sessionId = claims.get("session_id", String.class);

            // Vérifier que c'est bien un refresh token
            if (!"refresh".equals(claims.get("type"))) {
                throw new AuthenticationException("Type de token invalide");
            }

            // Vérifier que la session est toujours active
            AdminSession session = adminSessionRepository.findByIdAndAdminUserIdAndActiveTrue(sessionId, adminId)
                    .orElseThrow(() -> new AuthenticationException("Session invalide ou expirée"));

            // Mettre à jour l'activité de la session
            session.setLastActivity(LocalDateTime.now());
            adminSessionRepository.save(session);

            // Générer de nouveaux tokens
            String newAccessToken = generateAccessToken(session.getAdminUser(), sessionId);
            String newRefreshToken = generateRefreshToken(session.getAdminUser(), sessionId);

            // Invalider l'ancien refresh token
            blacklistToken(refreshToken);

            log.info("Tokens rafraîchis pour admin: {} - Session: {}", session.getAdminUser().getEmail(), sessionId);

            return AdminTokenResponse.success(newAccessToken, newRefreshToken, (long) accessTokenValiditySeconds);

        } catch (ExpiredJwtException e) {
            log.warn("Tentative d'utilisation d'un refresh token expiré");
            throw new AuthenticationException("Token expiré");
        } catch (JwtException e) {
            log.error("Erreur validation refresh token", e);
            throw new AuthenticationException("Token invalide");
        }
    }

    public boolean validateToken(String token) {
        try {
            if (isTokenBlacklisted(token)) {
                return false;
            }

            validateAndParseToken(token);
            return true;
        } catch (JwtException e) {
            log.debug("Token invalide: {}", e.getMessage());
            return false;
        }
    }

    public Claims validateAndParseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Map<String, Object> getSessionStatus(String adminId) {
        // Récupérer les sessions actives
        List<AdminSession> activeSessions = adminSessionRepository.findByAdminUserIdAndActiveTrue(adminId);

        if (activeSessions.isEmpty()) {
            return Map.of(
                    "hasActiveSession", false,
                    "sessionCount", 0
            );
        }

        AdminSession currentSession = activeSessions.get(0); // Prendre la plus récente

        return Map.of(
                "hasActiveSession", true,
                "sessionCount", activeSessions.size(),
                "sessionId", currentSession.getId(),
                "isActive", currentSession.isActive(),
                "createdAt", currentSession.getCreatedAt(),
                "lastActivity", currentSession.getLastActivity(),
                "expiresAt", currentSession.getExpiresAt(),
                "clientIp", currentSession.getClientIp()
        );
    }

    public void invalidateTokens(String adminId, String sessionId) {
        // Mettre en blacklist tous les tokens de cette session
        String tokenPattern = TOKEN_PREFIX + adminId + ":" + sessionId;
        String refreshPattern = REFRESH_TOKEN_PREFIX + adminId + ":" + sessionId;

        // Récupérer les tokens depuis Redis
        String accessToken = (String) redisTemplate.opsForValue().get(tokenPattern);
        String refreshToken = (String) redisTemplate.opsForValue().get(refreshPattern);

        if (accessToken != null) {
            blacklistToken(accessToken);
        }

        if (refreshToken != null) {
            blacklistToken(refreshToken);
        }

        // Supprimer les tokens du cache
        redisTemplate.delete(tokenPattern);
        redisTemplate.delete(refreshPattern);

        log.info("Tokens invalidés pour admin: {} - Session: {}", adminId, sessionId);
    }

    public void invalidateAllUserTokens(String adminId) {
        // Récupérer toutes les sessions actives
        List<AdminSession> activeSessions = adminSessionRepository.findByAdminUserIdAndActiveTrue(adminId);

        for (AdminSession session : activeSessions) {
            invalidateTokens(adminId, session.getId());

            // Désactiver la session
            session.setActive(false);
            session.setLogoutAt(LocalDateTime.now());
            adminSessionRepository.save(session);
        }

        log.info("Tous les tokens invalidés pour admin: {}", adminId);
    }

    private void blacklistToken(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            Date expiration = claims.getExpiration();

            long timeToLive = expiration.getTime() - System.currentTimeMillis();
            if (timeToLive > 0) {
                String blacklistKey = BLACKLIST_PREFIX + getTokenId(token);
                redisTemplate.opsForValue().set(blacklistKey, "blacklisted", timeToLive, TimeUnit.MILLISECONDS);
            }
        } catch (Exception e) {
            log.warn("Erreur lors de la mise en blacklist du token", e);
        }
    }

    private boolean isTokenBlacklisted(String token) {
        String blacklistKey = BLACKLIST_PREFIX + getTokenId(token);
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    private String getTokenId(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getSubject() + ":" + claims.get("session_id", String.class) + ":" + claims.getIssuedAt().getTime();
        } catch (Exception e) {
            return token.substring(Math.max(0, token.length() - 10));
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractAdminId(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.getSubject();
    }

    public String extractSessionId(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("session_id", String.class);
    }

    public List<String> extractPermissions(String token) {
        Claims claims = validateAndParseToken(token);
        return claims.get("permissions", List.class);
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException e) {
            return true;
        }
    }

    public long getTokenRemainingTime(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            long expiration = claims.getExpiration().getTime();
            long current = System.currentTimeMillis();
            return Math.max(0, expiration - current) / 1000;
        } catch (JwtException e) {
            return 0;
        }
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/service/KeycloakAdminService.java

```java
package com.lims.auth.service;

import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.KeycloakException;
import com.lims.auth.config.LimsAuthProperties;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

// ✅ Imports JAX-RS corrigés pour Jakarta EE
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.ProcessingException;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakAdminService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    @Value("${keycloak.admin.username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin.password:admin}")
    private String adminPassword;

    private final LimsAuthProperties authProperties;

    public String authenticate(String email, String password) {
        try {
            // Créer un client Keycloak pour l'authentification
            Keycloak keycloak = KeycloakBuilder.builder()
                    .serverUrl(authServerUrl)
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .username(email)
                    .password(password)
                    .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                    .build();

            // Tenter de récupérer le token pour valider les credentials
            String token = keycloak.tokenManager().getAccessTokenString();

            log.info("Authentification Keycloak réussie pour: {}", email);
            return token;

        } catch (NotAuthorizedException e) {
            log.warn("Échec authentification Keycloak pour: {}", email);
            throw new AuthenticationException("Identifiants invalides");
        } catch (ProcessingException e) {
            log.error("Erreur de connexion Keycloak pour: {}", email, e);
            throw new KeycloakException("Erreur de connexion au serveur d'authentification");
        } catch (Exception e) {
            log.error("Erreur authentification Keycloak pour: {}", email, e);
            throw new KeycloakException("Erreur lors de l'authentification");
        }
    }

    public String createAdminUser(String email, String firstName, String lastName, String password) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Créer la représentation utilisateur
            UserRepresentation user = new UserRepresentation();
            user.setUsername(email);
            user.setEmail(email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setEnabled(true);
            user.setEmailVerified(true);

            // Ajouter les attributs custom
            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("realm", Arrays.asList("lims-admin"));
            attributes.put("user_type", Arrays.asList("ADMIN"));
            attributes.put("created_by", Arrays.asList("system"));
            user.setAttributes(attributes);

            // Créer l'utilisateur
            Response response = usersResource.create(user);

            if (response.getStatus() != 201) {
                throw new KeycloakException("Erreur création utilisateur Keycloak: " + response.getStatus());
            }

            // Récupérer l'ID de l'utilisateur créé
            String userId = extractUserIdFromResponse(response);

            // Définir le mot de passe
            setUserPassword(usersResource, userId, password);

            // Ajouter les rôles admin
            assignAdminRoles(realmResource, userId);

            log.info("Utilisateur admin créé dans Keycloak: {} - ID: {}", email, userId);
            return userId;

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la création utilisateur Keycloak: {} - Status: {}",
                    email, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la création de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur création utilisateur admin Keycloak: {}", email, e);
            throw new KeycloakException("Erreur lors de la création de l'utilisateur");
        }
    }

    public void updateAdminUser(String userId, String firstName, String lastName) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            UserRepresentation user = userResource.toRepresentation();
            user.setFirstName(firstName);
            user.setLastName(lastName);

            userResource.update(user);

            log.info("Utilisateur admin mis à jour dans Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la mise à jour utilisateur Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la mise à jour de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur mise à jour utilisateur admin Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de la mise à jour de l'utilisateur");
        }
    }

    public void enableMfaForUser(String userId) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            // Configurer les actions requises pour forcer le setup MFA
            List<String> requiredActions = new ArrayList<>();
            requiredActions.add("CONFIGURE_TOTP");

            UserRepresentation user = userResource.toRepresentation();
            user.setRequiredActions(requiredActions);
            userResource.update(user);

            log.info("MFA activé pour utilisateur Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de l'activation MFA Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de l'activation MFA");
        } catch (Exception e) {
            log.error("Erreur activation MFA pour utilisateur Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de l'activation MFA");
        }
    }

    public void disableMfaForUser(String userId) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            // Supprimer les actions requises MFA
            UserRepresentation user = userResource.toRepresentation();
            user.setRequiredActions(Collections.emptyList());
            userResource.update(user);

            log.info("MFA désactivé pour utilisateur Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la désactivation MFA Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la désactivation MFA");
        } catch (Exception e) {
            log.error("Erreur désactivation MFA pour utilisateur Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de la désactivation MFA");
        }
    }

    public void disableUser(String userId) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            UserRepresentation user = userResource.toRepresentation();
            user.setEnabled(false);
            userResource.update(user);

            log.info("Utilisateur désactivé dans Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la désactivation utilisateur Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la désactivation de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur désactivation utilisateur Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de la désactivation de l'utilisateur");
        }
    }

    public void enableUser(String userId) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            UserRepresentation user = userResource.toRepresentation();
            user.setEnabled(true);
            userResource.update(user);

            log.info("Utilisateur activé dans Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de l'activation utilisateur Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de l'activation de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur activation utilisateur Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de l'activation de l'utilisateur");
        }
    }

    public void resetUserPassword(String userId, String newPassword) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            setUserPassword(usersResource, userId, newPassword);

            log.info("Mot de passe réinitialisé pour utilisateur Keycloak: {}", userId);

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la réinitialisation mot de passe Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la réinitialisation du mot de passe");
        } catch (Exception e) {
            log.error("Erreur réinitialisation mot de passe utilisateur Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de la réinitialisation du mot de passe");
        }
    }

    public List<UserRepresentation> getAllAdminUsers() {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Récupérer tous les utilisateurs du realm admin
            List<UserRepresentation> users = usersResource.list();

            // Filtrer les utilisateurs admin
            return users.stream()
                    .filter(user -> {
                        Map<String, List<String>> attributes = user.getAttributes();
                        return attributes != null &&
                                attributes.containsKey("user_type") &&
                                attributes.get("user_type").contains("ADMIN");
                    })
                    .toList();

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la récupération utilisateurs Keycloak - Status: {}",
                    e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la récupération des utilisateurs");
        } catch (Exception e) {
            log.error("Erreur récupération utilisateurs admin Keycloak", e);
            throw new KeycloakException("Erreur lors de la récupération des utilisateurs");
        }
    }

    public UserRepresentation getAdminUser(String userId) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);

            return userResource.toRepresentation();

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la récupération utilisateur Keycloak: {} - Status: {}",
                    userId, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la récupération de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur récupération utilisateur admin Keycloak: {}", userId, e);
            throw new KeycloakException("Erreur lors de la récupération de l'utilisateur");
        }
    }

    public Optional<UserRepresentation> findAdminUserByEmail(String email) {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            List<UserRepresentation> users = usersResource.search(email, true);

            return users.stream()
                    .filter(user -> {
                        Map<String, List<String>> attributes = user.getAttributes();
                        return attributes != null &&
                                attributes.containsKey("user_type") &&
                                attributes.get("user_type").contains("ADMIN");
                    })
                    .findFirst();

        } catch (WebApplicationException e) {
            log.error("Erreur HTTP lors de la recherche utilisateur Keycloak: {} - Status: {}",
                    email, e.getResponse().getStatus(), e);
            throw new KeycloakException("Erreur lors de la recherche de l'utilisateur");
        } catch (Exception e) {
            log.error("Erreur recherche utilisateur admin Keycloak: {}", email, e);
            throw new KeycloakException("Erreur lors de la recherche de l'utilisateur");
        }
    }

    private Keycloak getAdminKeycloakClient() {
        return KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm("master") // Utiliser le realm master pour l'administration
                .clientId("admin-cli")
                .username(adminUsername)
                .password(adminPassword)
                .build();
    }

    private String extractUserIdFromResponse(Response response) {
        String location = response.getHeaderString("Location");
        if (location != null) {
            return location.substring(location.lastIndexOf('/') + 1);
        }
        throw new KeycloakException("Impossible d'extraire l'ID utilisateur de la réponse");
    }

    private void setUserPassword(UsersResource usersResource, String userId, String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);

        UserResource userResource = usersResource.get(userId);
        userResource.resetPassword(credential);
    }

    private void assignAdminRoles(RealmResource realmResource, String userId) {
        try {
            // Récupérer les rôles du realm
            var realmRoles = realmResource.roles();

            // Assigner les rôles admin de base
            List<String> rolesToAssign = Arrays.asList("admin", "system_admin", "user_manager");

            for (String roleName : rolesToAssign) {
                try {
                    var role = realmRoles.get(roleName).toRepresentation();
                    realmResource.users().get(userId).roles().realmLevel().add(Arrays.asList(role));
                } catch (Exception e) {
                    log.warn("Rôle '{}' non trouvé dans Keycloak, ignoré", roleName);
                }
            }

        } catch (Exception e) {
            log.warn("Erreur assignation rôles admin pour utilisateur: {}", userId, e);
            // Ne pas faire échouer la création pour un problème de rôles
        }
    }

    public boolean isKeycloakAvailable() {
        try {
            Keycloak keycloak = getAdminKeycloakClient();
            keycloak.serverInfo().getInfo();
            return true;
        } catch (Exception e) {
            log.error("Keycloak non disponible", e);
            return false;
        }
    }

    public void validateMfaCode(String userId, String otpCode) {
        // Note: Keycloak ne fournit pas d'API directe pour valider les codes OTP
        // Cette validation est généralement faite lors de l'authentification
        // Pour un contrôle plus fin, il faudrait utiliser l'API TOTP directement
        log.debug("Validation MFA pour utilisateur Keycloak: {}", userId);
    }
}
```

# lims-auth-service/src/main/java/com/lims/auth/service/RateLimitService.java

```java
package com.lims.auth.service;

import com.lims.auth.config.LimsAuthProperties;
import com.lims.auth.exception.RateLimitException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final LimsAuthProperties authProperties;

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";
    private static final String LOCKOUT_PREFIX = "lockout:";

    /**
     * Vérifie et applique la limitation de taux pour un email donné
     */
    public void checkEmailRateLimit(String email) {
        String key = RATE_LIMIT_PREFIX + "email:" + email.toLowerCase();
        checkRateLimit(key, "email " + email);
    }

    /**
     * Vérifie et applique la limitation de taux pour une adresse IP donnée
     */
    public void checkIpRateLimit(String clientIp) {
        String key = RATE_LIMIT_PREFIX + "ip:" + clientIp;
        checkRateLimit(key, "IP " + clientIp);
    }

    /**
     * Vérifie et applique la limitation de taux pour un endpoint spécifique
     */
    public void checkEndpointRateLimit(String endpoint, String identifier) {
        String key = RATE_LIMIT_PREFIX + "endpoint:" + endpoint + ":" + identifier;
        checkRateLimit(key, "endpoint " + endpoint + " pour " + identifier);
    }

    /**
     * Incrémente le compteur de tentatives échouées pour un utilisateur
     */
    public void incrementFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts == 1) {
            // Première tentative échouée, définir l'expiration
            redisTemplate.expire(key, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
        }

        log.warn("Tentative échouée pour {}: {} tentatives", email, attempts);

        // Vérifier si l'utilisateur doit être verrouillé
        if (attempts >= authProperties.getSecurity().getMaxFailedAttempts()) {
            lockoutUser(email);
        }
    }

    /**
     * Réinitialise le compteur de tentatives échouées pour un utilisateur
     */
    public void resetFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        redisTemplate.delete(key);

        // Supprimer aussi le verrouillage éventuel
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        redisTemplate.delete(lockoutKey);

        log.info("Compteur de tentatives échouées réinitialisé pour {}", email);
    }

    /**
     * Vérifie si un utilisateur est verrouillé
     */
    public boolean isUserLockedOut(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        return redisTemplate.hasKey(lockoutKey);
    }

    /**
     * Obtient le nombre de tentatives échouées pour un utilisateur
     */
    public int getFailedAttempts(String email) {
        String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        Integer attempts = (Integer) redisTemplate.opsForValue().get(key);
        return attempts != null ? attempts : 0;
    }

    /**
     * Obtient le temps restant avant la réinitialisation du compteur
     */
    public long getRemainingLockoutTime(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        Long ttl = redisTemplate.getExpire(lockoutKey, TimeUnit.SECONDS);
        return ttl != null ? ttl : 0;
    }

    /**
     * Vérifie si une action spécifique est autorisée pour un utilisateur
     */
    public void checkActionRateLimit(String email, String action) {
        String key = RATE_LIMIT_PREFIX + "action:" + action + ":" + email.toLowerCase();
        checkRateLimit(key, "action " + action + " pour " + email);
    }

    /**
     * Applique un verrouillage temporaire pour un utilisateur
     */
    public void lockoutUser(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        redisTemplate.opsForValue().set(
                lockoutKey,
                System.currentTimeMillis(),
                authProperties.getSecurity().getLockoutDurationMinutes(),
                TimeUnit.MINUTES
        );

        log.warn("Utilisateur {} verrouillé temporairement pour {} minutes",
                email, authProperties.getSecurity().getLockoutDurationMinutes());
    }

    /**
     * Libère manuellement un utilisateur verrouillé
     */
    public void unlockUser(String email) {
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();
        String failedAttemptsKey = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();

        redisTemplate.delete(lockoutKey);
        redisTemplate.delete(failedAttemptsKey);

        log.info("Utilisateur {} déverrouillé manuellement", email);
    }

    /**
     * Vérifie la limitation de taux pour une clé donnée
     */
    private void checkRateLimit(String key, String description) {
        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts == 1) {
            // Première tentative, définir l'expiration
            redisTemplate.expire(key, authProperties.getRateLimit().getWindowMinutes(), TimeUnit.MINUTES);
        }

        if (attempts > authProperties.getRateLimit().getMaxAttempts()) {
            long remainingTime = redisTemplate.getExpire(key, TimeUnit.SECONDS);

            log.warn("Rate limit dépassé pour {}: {} tentatives", description, attempts);

            throw new RateLimitException(
                    String.format("Trop de tentatives pour %s. Réessayez dans %d minutes.",
                            description, remainingTime / 60),
                    0,
                    remainingTime * 1000
            );
        }

        log.debug("Rate limit OK pour {}: {}/{} tentatives",
                description, attempts, authProperties.getRateLimit().getMaxAttempts());
    }

    /**
     * Obtient les statistiques de limitation de taux pour un utilisateur
     */
    public RateLimitStatus getRateLimitStatus(String email) {
        String emailKey = RATE_LIMIT_PREFIX + "email:" + email.toLowerCase();
        String failedAttemptsKey = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
        String lockoutKey = LOCKOUT_PREFIX + email.toLowerCase();

        Integer currentAttempts = (Integer) redisTemplate.opsForValue().get(emailKey);
        Integer failedAttempts = (Integer) redisTemplate.opsForValue().get(failedAttemptsKey);
        boolean isLockedOut = redisTemplate.hasKey(lockoutKey);

        long remainingTime = 0;
        if (isLockedOut) {
            remainingTime = redisTemplate.getExpire(lockoutKey, TimeUnit.SECONDS);
        }

        return RateLimitStatus.builder()
                .currentAttempts(currentAttempts != null ? currentAttempts : 0)
                .maxAttempts(authProperties.getRateLimit().getMaxAttempts())
                .failedAttempts(failedAttempts != null ? failedAttempts : 0)
                .maxFailedAttempts(authProperties.getSecurity().getMaxFailedAttempts())
                .isLockedOut(isLockedOut)
                .remainingLockoutTimeSeconds(remainingTime)
                .build();
    }

    /**
     * Nettoie les anciens enregistrements de limitation de taux
     */
    public void cleanup() {
        // Cette méthode pourrait être appelée par un scheduler
        // pour nettoyer les anciennes entrées expirées
        log.debug("Nettoyage des limitations de taux expiré");
    }

    @lombok.Data
    @lombok.Builder
    public static class RateLimitStatus {
        private int currentAttempts;
        private int maxAttempts;
        private int failedAttempts;
        private int maxFailedAttempts;
        private boolean isLockedOut;
        private long remainingLockoutTimeSeconds;

        public boolean isNearLimit() {
            return currentAttempts >= (maxAttempts * 0.8);
        }

        public boolean isAtLimit() {
            return currentAttempts >= maxAttempts;
        }

        public int getRemainingAttempts() {
            return Math.max(0, maxAttempts - currentAttempts);
        }
    }
}
```

# lims-auth-service/src/main/resources/application-prod.yml

```yml
server:
  port: 8090
  compression:
    enabled: true
  http2:
    enabled: true

spring:
  application:
    name: lims-auth-service
  profiles:
    active: prod

  # Database configuration (Production)
  datasource:
    url: ${DATABASE_URL:jdbc:postgresql://localhost:5432/lims_db}
    username: ${DATABASE_USERNAME:lims_user}
    password: ${DATABASE_PASSWORD}
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: LIMS-Auth-Pool-Prod
      minimum-idle: 10
      maximum-pool-size: 50
      idle-timeout: 600000
      max-lifetime: 1800000
      connection-timeout: 30000
      leak-detection-threshold: 60000

  # JPA Configuration (Production)
  jpa:
    hibernate:
      ddl-auto: validate  # Pas de modification automatique en production
      default_schema: lims_auth
    show-sql: false  # Pas de logs SQL en production
    open-in-view: false
    properties:
      hibernate:
        format_sql: false
        default_schema: lims_auth
        jdbc:
          batch_size: 50
        order_inserts: true
        order_updates: true
        batch_versioned_data: true

  # Redis Configuration (Production)
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD}
      timeout: 2000ms
      jedis:
        pool:
          max-active: 20
          max-idle: 10
          min-idle: 5

# Keycloak Configuration (Production)
keycloak:
  enabled: true
  auth-server-url: ${KEYCLOAK_SERVER_URL:http://localhost:8080}
  realm: ${KEYCLOAK_REALM:lims-admin}
  resource: ${KEYCLOAK_CLIENT_ID:auth-service}
  credentials:
    secret: ${KEYCLOAK_CLIENT_SECRET}

# Security configuration (Production)
security:
  oauth2:
    resourceserver:
      jwt:
        issuer-uri: ${KEYCLOAK_SERVER_URL:http://localhost:8080}/realms/${KEYCLOAK_REALM:lims-admin}
        jwk-set-uri: ${KEYCLOAK_SERVER_URL:http://localhost:8080}/realms/${KEYCLOAK_REALM:lims-admin}/protocol/openid-connect/certs

# LIMS Configuration
lims:
  auth:
    mfa:
      issuer: "LIMS-Production-System"
      backup-codes:
        count: 10
        length: 8
      setup-token:
        expiry: 600
      reset-token:
        expiry: 86400

    rate-limiting:
      max-attempts: 3
      window-minutes: 15

    session:
      timeout: 7200
      extend-on-activity: true

# Management endpoints (Production)
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
  metrics:
    export:
      prometheus:
        enabled: true

# Logging (Production)
logging:
  level:
    com.lims.auth: INFO
    org.springframework.security: WARN
    org.hibernate.SQL: WARN
    org.keycloak: WARN
    org.springframework.web: WARN
    org.hibernate: WARN
    com.zaxxer.hikari: WARN
    org.apache.http: WARN
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: /var/log/lims/auth-service.log
    max-size: 100MB
    max-history: 30

# SpringDoc OpenAPI (Production)
springdoc:
  api-docs:
    enabled: false  # Désactiver en production
  swagger-ui:
    enabled: false  # Désactiver en production
```

# lims-auth-service/src/main/resources/application.yml

```yml
server:
  port: 8090

spring:
  application:
    name: lims-auth-service
  profiles:
    active: development

  # Database configuration
  datasource:
    url: jdbc:postgresql://localhost:5432/lims_db
    username: lims_user
    password: dev_password_123
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: LIMS-Auth-Pool
      minimum-idle: 5
      maximum-pool-size: 20
      idle-timeout: 300000
      max-lifetime: 1200000
      connection-timeout: 20000
      leak-detection-threshold: 60000

  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: none
      default_schema: lims_auth
    show-sql: true
    open-in-view: false  # Désactiver pour éviter le warning
    properties:
      hibernate:
        # Supprimer dialect (auto-détecté par Hibernate)
        format_sql: true
        default_schema: lims_auth
        # Optimisations de performance
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
        batch_versioned_data: true

  # Redis Configuration
  data:
    redis:
      host: localhost
      port: 6379
      password: redis_dev_123
      timeout: 2000ms
      jedis:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0

# Keycloak Configuration
keycloak:
  enabled: false  # Désactivé temporairement pour les tests de base
  auth-server-url: http://auth.lims.local
  realm: lims-admin
  resource: auth-service
  credentials:
    secret: dev-auth-admin-secret-123

# Security configuration
security:
  oauth2:
    resourceserver:
      jwt:
        issuer-uri: http://auth.lims.local/realms/lims-admin
        jwk-set-uri: http://auth.lims.local/realms/lims-admin/protocol/openid-connect/certs

# LIMS Configuration
lims:
  auth:
    jwt:
      secret: "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU="
    mfa:
      issuer: "LIMS-Admin-System"
      backup-codes:
        count: 10
        length: 8
      setup-token:
        expiry: 600 # 10 minutes
      reset-token:
        expiry: 86400 # 24 heures
    rate-limiting:
      max-attempts: 3
      window-minutes: 15
    session:
      timeout: 7200 # 2 heures
      extend-on-activity: true

# Management endpoints
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always

# Logging
logging:
  level:
    com.lims.auth: DEBUG
    org.springframework.security: INFO
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    org.keycloak: INFO
    # Réduire les warnings Hibernate
    org.hibernate.engine.jdbc.env.internal.LobCreatorBuilderImpl: WARN
    org.hibernate.dialect.Dialect: WARN
    org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean: INFO
    com.zaxxer.hikari.HikariConfig: INFO
    com.zaxxer.hikari.HikariDataSource: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

# SpringDoc OpenAPI
springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui.html
    enabled: true
```

# lims-laboratory-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.lims</groupId>
        <artifactId>lims-system</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>lims-laboratory-service</artifactId>
    <packaging>jar</packaging>

    <name>LIMS Laboratory Service</name>
    <description>Laboratory management service for LIMS</description>

    <dependencies>
        <!-- Spring Boot Starters -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- PostgreSQL Driver -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- Spring Security OAuth2 JOSE -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-jose</artifactId>
        </dependency>

        <!-- Development Tools -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

# lims-laboratory-service/src/main/java/com/lims/laboratory/controller/LaboratoryController.java

```java
package com.lims.laboratory.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/laboratory")
public class LaboratoryController {

    @GetMapping("/hello")
    public ResponseEntity<Map<String, Object>> hello() {
        return ResponseEntity.ok(Map.of(
                "message", "Hello from LIMS Laboratory Service!",
                "service", "lims-laboratory-service",
                "timestamp", LocalDateTime.now(),
                "port", 8082
        ));
    }
}
```

# lims-laboratory-service/src/main/java/com/lims/laboratory/LaboratoryServiceApplication.java

```java
package com.lims.laboratory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class LaboratoryServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(LaboratoryServiceApplication.class, args);
    }
}
```

# lims-laboratory-service/src/main/resources/application.yml

```yml
server:
  port: 8091

spring:
  application:
    name: lims-laboratory-service
  profiles:
    active: development

  # Database configuration
  datasource:
    url: jdbc:postgresql://localhost:5432/lims_core
    username: lims_user
    password: lims_password
    driver-class-name: org.postgresql.Driver

  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true

# Security configuration (to be configured with Keycloak)
security:
  oauth2:
    resourceserver:
      jwt:
        issuer-uri: http://localhost:8080/realms/lims-staff
        jwk-set-uri: http://localhost:8080/realms/lims-staff/protocol/openid-connect/certs

# Logging
logging:
  level:
    com.lims.laboratory: DEBUG
    org.springframework.security: DEBUG
    org.hibernate.SQL: DEBUG
```

# lims-patient-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.lims</groupId>
    <artifactId>lims-patient-service</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>LIMS Patient Service</name>
    <description>Service de gestion des patients pour le système LIMS</description>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring.boot.version>3.2.1</spring.boot.version>
        <spring.security.version>6.2.1</spring.security.version>
        <testcontainers.version>1.19.3</testcontainers.version>
        <mapstruct.version>1.6.3</mapstruct.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring.boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <!-- Spring Boot Starters -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>

        <!-- Spring Security & OAuth2 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-jose</artifactId>
        </dependency>

        <!-- Database -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- JSON Processing -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>

        <!-- JWT Token Processing -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.6</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.6</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.12.6</version>
            <scope>runtime</scope>
        </dependency>

        <!-- OpenAPI Documentation -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>2.2.0</version>
        </dependency>

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- MapStruct -->
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>${mapstruct.version}</version>
        </dependency>

        <!-- Development Tools -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>postgresql</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

# lims-patient-service/src/main/java/com/lims/Main.java

```java
package com.lims;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/PatientJwtAuthenticationConverter.java

```java
package com.lims.patient.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Convertisseur JWT pour le service Patient
 *
 * Gère les tokens JWT provenant de deux realms :
 * - lims-patient : Pour les patients (accès lecture seule à leurs données)
 * - lims-staff : Pour le staff médical (accès complet CRUD)
 *
 * Similaire à AdminJwtAuthenticationConverter du service auth
 */
@Component
@Slf4j
public class PatientJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public PatientJwtAuthenticationConverter() {
        // Configurer le converter pour extraire les authorities customisées
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        try {
            // Extraire le realm du token via l'issuer
            String issuer = jwt.getIssuer() != null ? jwt.getIssuer().toString() : "";
            String realm = extractRealmFromIssuer(issuer);

            log.debug("Processing JWT from realm: {} for subject: {}", realm, jwt.getSubject());

            // Traitement selon le realm
            return switch (realm) {
                case "lims-patient" -> extractPatientAuthorities(jwt);
                case "lims-staff" -> extractStaffAuthorities(jwt);
                case "lims-admin" -> extractAdminAuthorities(jwt); // Support pour les admins système
                default -> {
                    log.warn("Unknown or unsupported realm in JWT: {}", realm);
                    yield Collections.emptyList();
                }
            };

        } catch (Exception e) {
            log.error("Error processing JWT authorities: {}", e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Extrait le nom du realm depuis l'issuer URI
     * Format attendu: http://localhost:8080/realms/lims-patient
     */
    private String extractRealmFromIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return "unknown";
        }

        if (issuer.contains("/realms/")) {
            String[] parts = issuer.split("/realms/");
            if (parts.length > 1) {
                return parts[1];
            }
        }

        return "unknown";
    }

    /**
     * Extrait les autorités pour un token patient (realm lims-patient)
     */
    private Collection<GrantedAuthority> extractPatientAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"PATIENT".equals(userType)) {
            log.warn("Invalid user_type for patient realm: {}", userType);
            return Collections.emptyList();
        }

        // Les patients ont uniquement le rôle PATIENT
        log.debug("Granting PATIENT role for user: {}", jwt.getSubject());
        return List.of(new SimpleGrantedAuthority("ROLE_PATIENT"));
    }

    /**
     * Extrait les autorités pour un token staff (realm lims-staff)
     */
    private Collection<GrantedAuthority> extractStaffAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"STAFF".equals(userType)) {
            log.warn("Invalid user_type for staff realm: {}", userType);
            return Collections.emptyList();
        }

        // Extraire les authorities par défaut
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

        // Ajouter les rôles spécifiques du realm staff
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                Collection<GrantedAuthority> realmAuthorities = roles.stream()
                        .filter(this::isValidStaffRole)
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Combiner les authorities
                Collection<GrantedAuthority> combinedAuthorities = Stream.concat(authorities.stream(), realmAuthorities.stream())
                        .collect(Collectors.toList());

                log.debug("Granted authorities for staff user {}: {}", jwt.getSubject(), combinedAuthorities);
                return combinedAuthorities;
            }
        }

        log.warn("No realm_access found in staff JWT for user: {}", jwt.getSubject());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token admin (realm lims-admin)
     * Permet aux admins système d'accéder aux données patient
     */
    private Collection<GrantedAuthority> extractAdminAuthorities(Jwt jwt) {
        // Vérifier le type d'utilisateur
        String userType = jwt.getClaimAsString("user_type");
        if (!"ADMIN".equals(userType)) {
            log.warn("Invalid user_type for admin realm: {}", userType);
            return Collections.emptyList();
        }

        // Extraire les authorities par défaut
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(jwt);

        // Ajouter les rôles spécifiques du realm admin
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            if (roles != null) {
                Collection<GrantedAuthority> realmAuthorities = roles.stream()
                        .filter(this::isValidAdminRole)
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList());

                // Combiner les authorities
                Collection<GrantedAuthority> combinedAuthorities = Stream.concat(authorities.stream(), realmAuthorities.stream())
                        .collect(Collectors.toList());

                log.debug("Granted authorities for admin user {}: {}", jwt.getSubject(), combinedAuthorities);
                return combinedAuthorities;
            }
        }

        return authorities;
    }

    /**
     * Valide si le rôle est autorisé pour le staff
     */
    private boolean isValidStaffRole(String role) {
        return List.of("ADMIN", "SECRETAIRE", "PRELEVEUR", "TECHNICIEN", "RESPONSABLE_QUALITE", "STAFF")
                .contains(role);
    }

    /**
     * Valide si le rôle est autorisé pour les admins
     */
    private boolean isValidAdminRole(String role) {
        return List.of("SUPER_ADMIN", "SYSTEM_ADMIN", "SECURITY_ADMIN", "SUPPORT_ADMIN", "ADMIN")
                .contains(role);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/SecurityConfig.java

```java
package com.lims.patient.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Configuration de sécurité pour le service Patient LIMS
 *
 * Configuration unifiée pour tous les environnements :
 * - Supporte OAuth2 JWT avec realms lims-patient et lims-staff
 * - Endpoints publics pour les tests et health checks
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        // Endpoints publics (pas d'authentification)
                        .requestMatchers(
                                "/api/v1/patients/info/**",
                                "/actuator/health",
                                "/actuator/info",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        // Endpoints de test (développement)
                        .requestMatchers("/api/v1/patients/me/test").hasRole("PATIENT")
                        .requestMatchers("/api/v1/patients/test/staff").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/test/mixed").hasAnyRole("PATIENT", "STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Gestion des patients
                        .requestMatchers("GET", "/api/v1/patients").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("POST", "/api/v1/patients").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("GET", "/api/v1/patients/{id}").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("PUT", "/api/v1/patients/{id}").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("DELETE", "/api/v1/patients/{id}").hasAnyRole("ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Recherche
                        .requestMatchers("/api/v1/patients/search/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/by-nir/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/by-phone/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/check-duplicates").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Assurances et ordonnances
                        .requestMatchers("/api/v1/patients/{id}/insurances/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/{id}/prescriptions/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/prescriptions/**").hasAnyRole("STAFF", "ADMIN", "SECRETAIRE")

                        // Endpoints Staff - Analytics et exports (accès restreint)
                        .requestMatchers("/api/v1/patients/statistics").hasAnyRole("ADMIN", "SECRETAIRE")
                        .requestMatchers("/api/v1/patients/export").hasRole("ADMIN")
                        .requestMatchers("/api/v1/patients/rgpd-compliance").hasRole("ADMIN")
                        .requestMatchers("/api/v1/patients/batch").hasAnyRole("ADMIN", "SECRETAIRE")

                        // Endpoints Patient - Données personnelles
                        .requestMatchers("/api/v1/patients/me/**").hasRole("PATIENT")

                        // Endpoints d'intégration et webhooks
                        .requestMatchers("/api/v1/webhooks/**").permitAll() // Authentification par signature
                        .requestMatchers("/api/v1/integration/**").hasRole("ADMIN")

                        // Actuator - monitoring complet pour admin seulement
                        .requestMatchers("/actuator/**").permitAll() // En dev, tout est accessible

                        // Fallback : toute autre requête nécessite une authentification
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new PatientJwtAuthenticationConverter();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/controller/InfoController.java

```java
package com.lims.patient.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Contrôleur principal du service Patient
 *
 * Ce contrôleur fournira les endpoints pour :
 * - Auto-enregistrement des patients
 * - Gestion des profils patients
 * - Consultation des données personnelles
 * - Prise de rendez-vous
 */
@RestController
@RequestMapping("/api/v1/patients/info")
@Tag(name = "Patient Management", description = "API de gestion des patients LIMS")
@Slf4j
public class InfoController {

    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${server.port}")
    private int serverPort;

    @Operation(
            summary = "Vérification de l'état du service",
            description = "Endpoint de health check pour le monitoring"
    )
    @GetMapping("/_health")
    public ResponseEntity<Map<String, Object>> health() {
        log.debug("Health check endpoint appelé");

        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "lims-patient-service",
                "realm", "lims-patient",
                "timestamp", LocalDateTime.now(),
                "checks", Map.of(
                        "database", "UP",  // TODO: Ajouter vraie vérification DB
                        "redis", "UP",     // TODO: Ajouter vraie vérification Redis
                        "keycloak", "UP"   // TODO: Ajouter vraie vérification Keycloak
                )
        ));
    }

    @Operation(
            summary = "Informations sur l'API Patient",
            description = "Retourne les informations détaillées sur l'API et ses capacités"
    )
    @GetMapping("")
    public ResponseEntity<Map<String, Object>> info() {
        return ResponseEntity.ok(Map.of(
                "service", Map.of(
                        "name", "LIMS Patient Service",
                        "description", "Service de gestion des patients pour le système LIMS",
                        "version", "1.0.0",
                        "realm", "lims-patient",
                        "port", serverPort
                ),
                "capabilities", Map.of(
                        "patient-registration", "Auto-enregistrement avec validation email",
                        "otp-authentication", "Authentification OTP par email/SMS",
                        "profile-management", "Gestion du profil patient",
                        "appointment-booking", "Prise de rendez-vous en ligne",
                        "document-access", "Accès aux ordonnances et résultats",
                        "notification", "Notifications email/SMS"
                ),
                "security", Map.of(
                        "realm", "lims-patient",
                        "auth-method", "OAuth2 + OTP",
                        "data-encryption", true,
                        "audit-trail", true
                ),
                "api", Map.of(
                        "version", "v1",
                        "documentation", "/swagger-ui.html",
                        "openapi", "/api-docs"
                )
        ));
    }

    /**
     * Détecte le profil Spring actif
     */
    private String getActiveProfile() {
        // Cette méthode pourrait être améliorée avec @Value("${spring.profiles.active}")
        return "development"; // Par défaut
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/PatientServiceApplication.java

```java
package com.lims.patient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Application principale du service Patient LIMS
 *
 * Ce service gère :
 * - Auto-enregistrement des patients
 * - Authentification OTP (Email/SMS)
 * - Gestion des données patients
 * - Intégration avec le realm Keycloak lims-patient
 *
 * Port: 8083
 * Realm Keycloak: lims-patient
 * Base de données: lims_core.patients
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableCaching
@EnableAsync
public class PatientServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PatientServiceApplication.class, args);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/security/PatientSecurityContext.java

```java
package com.lims.patient.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

/**
 * Utilitaire pour accéder au contexte de sécurité du service Patient
 *
 * Fournit des méthodes pour :
 * - Extraire l'ID du patient connecté
 * - Vérifier les permissions d'accès aux données
 * - Valider l'appartenance des données à l'utilisateur connecté
 */
@Component
@Slf4j
public class PatientSecurityContext {

    /**
     * Récupère l'ID du patient actuellement connecté
     * @return ID du patient ou null si pas connecté
     */
    public String getCurrentPatientId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        // Si c'est un JWT, extraire le subject (patient ID)
        if (auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }

        return auth.getName();
    }

    /**
     * Récupère l'ID du staff actuellement connecté
     * @return ID du staff ou null si pas connecté ou pas staff
     */
    public String getCurrentStaffId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        // Vérifier que c'est bien un staff
        if (!hasRole("STAFF") && !hasRole("ADMIN") && !hasRole("SECRETAIRE")) {
            return null;
        }

        if (auth.getPrincipal() instanceof Jwt jwt) {
            return jwt.getSubject();
        }

        return auth.getName();
    }

    /**
     * Vérifie si l'utilisateur connecté a un rôle spécifique
     */
    public boolean hasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals(roleWithPrefix));
    }

    /**
     * Vérifie si l'utilisateur connecté est un patient
     */
    public boolean isPatient() {
        return hasRole("PATIENT");
    }

    /**
     * Vérifie si l'utilisateur connecté est du staff
     */
    public boolean isStaff() {
        return hasRole("STAFF") || hasRole("ADMIN") || hasRole("SECRETAIRE") ||
                hasRole("PRELEVEUR") || hasRole("TECHNICIEN") || hasRole("RESPONSABLE_QUALITE");
    }

    /**
     * Vérifie si l'utilisateur connecté est admin
     */
    public boolean isAdmin() {
        return hasRole("ADMIN") || hasRole("SUPER_ADMIN");
    }

    /**
     * Vérifie si un patient peut accéder à ses propres données
     * @param patientId ID du patient dont on veut accéder aux données
     * @return true si l'accès est autorisé
     */
    public boolean canAccessPatientData(String patientId) {
        // Le staff peut accéder à toutes les données patient
        if (isStaff()) {
            log.debug("Staff user {} accessing patient data {}", getCurrentStaffId(), patientId);
            return true;
        }

        // Un patient ne peut accéder qu'à ses propres données
        if (isPatient()) {
            String currentPatientId = getCurrentPatientId();
            boolean canAccess = patientId.equals(currentPatientId);

            if (!canAccess) {
                log.warn("Patient {} attempted to access data of patient {}", currentPatientId, patientId);
            }

            return canAccess;
        }

        // Aucun autre type d'utilisateur ne peut accéder aux données patient
        return false;
    }

    /**
     * Récupère le JWT complet pour accéder à des claims spécifiques
     */
    public Jwt getCurrentJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return jwt;
        }
        return null;
    }

    /**
     * Récupère une claim spécifique du JWT
     */
    public String getJwtClaim(String claimName) {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString(claimName) : null;
    }

    /**
     * Récupère l'ID du laboratoire pour un staff
     */
    public String getCurrentLaboratoryId() {
        if (!isStaff()) {
            return null;
        }
        return getJwtClaim("laboratory_id");
    }

    /**
     * Récupère le type d'utilisateur depuis le JWT
     */
    public String getUserType() {
        return getJwtClaim("user_type");
    }

    /**
     * Récupère le realm depuis le JWT
     */
    public String getRealm() {
        return getJwtClaim("realm");
    }

    /**
     * Récupère l'email de l'utilisateur connecté
     */
    public String getCurrentUserEmail() {
        return getJwtClaim("email");
    }

    /**
     * Vérifie si l'utilisateur connecté a vérifié son MFA (pour staff/admin)
     */
    public boolean isMfaVerified() {
        Jwt jwt = getCurrentJwt();
        if (jwt == null) {
            return false;
        }

        Boolean mfaVerified = jwt.getClaimAsBoolean("mfa_verified");
        return Boolean.TRUE.equals(mfaVerified);
    }

    /**
     * Récupère l'ID de session pour l'audit
     */
    public String getSessionId() {
        return getJwtClaim("session_id");
    }

    /**
     * Récupère des informations complètes sur l'utilisateur connecté
     */
    public UserInfo getCurrentUserInfo() {
        Jwt jwt = getCurrentJwt();
        if (jwt == null) {
            return null;
        }

        return UserInfo.builder()
                .userId(jwt.getSubject())
                .email(getJwtClaim("email"))
                .userType(getUserType())
                .realm(getRealm())
                .laboratoryId(getCurrentLaboratoryId())
                .sessionId(getSessionId())
                .isPatient(isPatient())
                .isStaff(isStaff())
                .isAdmin(isAdmin())
                .mfaVerified(isMfaVerified())
                .build();
    }

    /**
     * Classe pour encapsuler les informations utilisateur
     */
    @lombok.Data
    @lombok.Builder
    public static class UserInfo {
        private String userId;
        private String email;
        private String userType;
        private String realm;
        private String laboratoryId;
        private String sessionId;
        private boolean isPatient;
        private boolean isStaff;
        private boolean isAdmin;
        private boolean mfaVerified;
    }
}
```

# lims-patient-service/src/main/resources/application.yml

```yml
server:
  port: 8092

spring:
  application:
    name: lims-patient-service
  profiles:
    active: development

  # Database configuration - Schema patients
  datasource:
    url: jdbc:postgresql://localhost:5432/lims_db
    username: lims_user
    password: dev_password_123
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: LIMS-Patient-Pool
      minimum-idle: 5
      maximum-pool-size: 20
      idle-timeout: 300000
      max-lifetime: 1200000
      connection-timeout: 20000
      leak-detection-threshold: 60000

  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: validate  # En production, utilisez 'validate'
      default_schema: lims_patient
    show-sql: true
    open-in-view: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        default_schema: lims_patient
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
        batch_versioned_data: true

  # Redis Configuration pour cache sessions patients
  data:
    redis:
      host: localhost
      port: 6379
      password: redis_dev_123
      timeout: 2000ms
      database: 2  # Base dédiée aux patients
      jedis:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0

# Keycloak Configuration - Realm Patient
keycloak:
  enabled: true
  auth-server-url: http://localhost:8080
  realm: lims-patient
  resource: patient-service
  credentials:
    secret: dev-patient-secret-123

# OAuth2 Resource Server Configuration
security:
  oauth2:
    resourceserver:
      jwt:
        # Spring récupère les clés publiques UNE FOIS au démarrage
        jwk-set-uri: http://auth.lims.local/realms/lims-patient/protocol/openid-connect/certs

# Configuration spécifique LIMS Patient
lims:
  patient:
    registration:
      email-verification-required: true
      auto-activation: false  # Validation manuelle par le staff
      max-pending-registrations: 1000

    otp:
      provider: email  # Options: email, sms, both
      validity-minutes: 10
      max-attempts: 3

    data-access:
      allowed-staff-realms:
        - lims-staff
      audit-all-access: true

    business-rules:
      max-appointments-per-day: 5
      appointment-window-days: 30

# Monitoring et Actuator
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
  metrics:
    export:
      prometheus:
        enabled: true

# OpenAPI Documentation
springdoc:
  api-docs:
    path: /api-docs
  swagger-ui:
    path: /swagger-ui.html

# Logging Configuration
logging:
  level:
    com.lims.patient: DEBUG
    org.springframework.security: DEBUG
    org.hibernate.SQL: DEBUG
    org.springframework.web: WARN
    org.springframework.transaction: WARN
    org.springframework.orm: WARN
    org.springframework.aop: WARN
    org.springframework.cache: WARN
    org.springframework.data: WARN
    org.springframework.context: WARN
    org.springframework.beans: WARN
    org.springframework.boot: INFO
    org.springframework.security.oauth2: DEBUG
    org.springframework.security.web: DEBUG
    org.keycloak: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: /var/log/lims/patient-service.log
    max-size: 100MB
    max-history: 30

---
# Profil développement
spring:
  config:
    activate:
      on-profile: development

  # En développement, on peut être plus permissif
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect

keycloak:
  enabled: false  # Désactivé pour les tests locaux sans Keycloak

# Logging plus verbeux en dev
logging:
  level:
    com.lims.patient: TRACE
    org.springframework.security: TRACE

---
# Profil production
spring:
  config:
    activate:
      on-profile: production

  # Configuration stricte en production
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect

keycloak:
  enabled: true
  auth-server-url: https://auth.lims.local

# Logs optimisés pour la production
logging:
  level:
    com.lims.patient: INFO
    org.springframework.security: WARN
    org.hibernate.SQL: WARN

# SpringDoc désactivé en production
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false
```

# pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.lims</groupId>
    <artifactId>lims-system</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <name>LIMS System</name>
    <description>Laboratory Information Management System</description>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring.boot.version>3.4.0</spring.boot.version>
        <spring.security.version>6.2.1</spring.security.version>
        <keycloak.version>26.0.5</keycloak.version>
        <postgresql.version>42.7.3</postgresql.version>
        <maven.compiler.plugin.version>3.12.1</maven.compiler.plugin.version>
        <maven.surefire.plugin.version>3.2.5</maven.surefire.plugin.version>
        <maven.failsafe.plugin.version>3.2.5</maven.failsafe.plugin.version>
        <mapstruct.version>1.6.0</mapstruct.version>
        <lombok.version>1.18.34</lombok.version>
    </properties>

    <!-- ✅ Modules sans duplication -->
    <modules>
        <module>lims-auth-service</module>
        <module>lims-laboratory-service</module>
        <module>lims-patient-service</module>
    </modules>

    <dependencyManagement>
        <dependencies>
            <!-- Spring Boot BOM -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring.boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- PostgreSQL Driver -->
            <dependency>
                <groupId>org.postgresql</groupId>
                <artifactId>postgresql</artifactId>
                <version>${postgresql.version}</version>
            </dependency>

            <!-- Spring Security OAuth2 -->
            <dependency>
                <groupId>org.springframework.security</groupId>
                <artifactId>spring-security-oauth2-jose</artifactId>
                <version>${spring.security.version}</version>
            </dependency>

            <!-- Spring Security OAuth2 Resource Server -->
            <dependency>
                <groupId>org.springframework.security</groupId>
                <artifactId>spring-security-oauth2-resource-server</artifactId>
                <version>${spring.security.version}</version>
            </dependency>

            <!-- Keycloak Admin Client -->
            <dependency>
                <groupId>org.keycloak</groupId>
                <artifactId>keycloak-admin-client</artifactId>
                <version>${keycloak.version}</version>
            </dependency>

            <!-- Validation -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-validation</artifactId>
                <version>${spring.boot.version}</version>
            </dependency>

            <!-- Testing -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-test</artifactId>
                <version>${spring.boot.version}</version>
                <scope>test</scope>
            </dependency>

            <!-- Testcontainers -->
            <dependency>
                <groupId>org.testcontainers</groupId>
                <artifactId>testcontainers-bom</artifactId>
                <version>1.19.3</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- MapStruct -->
            <dependency>
                <groupId>org.mapstruct</groupId>
                <artifactId>mapstruct</artifactId>
                <version>${mapstruct.version}</version>
            </dependency>
            <dependency>
                <groupId>org.mapstruct</groupId>
                <artifactId>mapstruct-processor</artifactId>
                <version>${mapstruct.version}</version>
                <scope>provided</scope>
            </dependency>

            <!-- Lombok (compatibilité MapStruct) -->
            <dependency>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok</artifactId>
                <version>${lombok.version}</version>
                <scope>provided</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <pluginManagement>
            <plugins>
                <!-- Spring Boot Maven Plugin -->
                <plugin>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-maven-plugin</artifactId>
                    <version>${spring.boot.version}</version>
                    <configuration>
                        <excludes>
                            <exclude>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok</artifactId>
                            </exclude>
                        </excludes>
                    </configuration>
                </plugin>

                <!-- Maven Compiler Plugin -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>${maven.compiler.plugin.version}</version>
                    <configuration>
                        <source>21</source>
                        <target>21</target>
                        <encoding>UTF-8</encoding>
                        <parameters>true</parameters>
                        <annotationProcessorPaths>
                            <!-- MapStruct Processor -->
                            <path>
                                <groupId>org.mapstruct</groupId>
                                <artifactId>mapstruct-processor</artifactId>
                                <version>${mapstruct.version}</version>
                            </path>
                            <!-- Lombok -->
                            <path>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok</artifactId>
                                <version>${lombok.version}</version>
                            </path>
                            <!-- Lombok MapStruct Binding -->
                            <path>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok-mapstruct-binding</artifactId>
                                <version>0.2.0</version>
                            </path>
                        </annotationProcessorPaths>
                    </configuration>
                </plugin>

                <!-- Maven Surefire Plugin (Unit Tests) -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-surefire-plugin</artifactId>
                    <version>${maven.surefire.plugin.version}</version>
                    <configuration>
                        <useSystemClassLoader>false</useSystemClassLoader>
                    </configuration>
                </plugin>

                <!-- Maven Failsafe Plugin (Integration Tests) -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-failsafe-plugin</artifactId>
                    <version>${maven.failsafe.plugin.version}</version>
                    <executions>
                        <execution>
                            <goals>
                                <goal>integration-test</goal>
                                <goal>verify</goal>
                            </goals>
                        </execution>
                    </executions>
                </plugin>

                <!-- Maven Resources Plugin -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-resources-plugin</artifactId>
                    <version>3.3.1</version>
                    <configuration>
                        <encoding>UTF-8</encoding>
                    </configuration>
                </plugin>

                <!-- Maven Clean Plugin -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-clean-plugin</artifactId>
                    <version>3.3.2</version>
                </plugin>

                <!-- Maven Install Plugin -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-install-plugin</artifactId>
                    <version>3.1.1</version>
                </plugin>

                <!-- Maven Deploy Plugin -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-deploy-plugin</artifactId>
                    <version>3.1.1</version>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>

    <!-- Profils pour différents environnements -->
    <profiles>
        <profile>
            <id>dev</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <properties>
                <spring.profiles.active>dev</spring.profiles.active>
            </properties>
        </profile>

        <profile>
            <id>prod</id>
            <properties>
                <spring.profiles.active>prod</spring.profiles.active>
            </properties>
        </profile>

        <profile>
            <id>docker</id>
            <properties>
                <spring.profiles.active>docker</spring.profiles.active>
            </properties>
        </profile>
    </profiles>
</project>
```

