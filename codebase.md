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

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${lims.auth.jwt.secret}")
    private String jwtSecret;

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
        // Utiliser la même clé HMAC pour la validation
        try {
            byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        } catch (IllegalArgumentException e) {
            // Fallback si pas Base64
            SecretKeySpec secretKey = new SecretKeySpec(
                    jwtSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA512");
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        }
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
import com.lims.auth.dto.request.AdminLogoutRequest;
import com.lims.auth.dto.request.AdminMfaVerifyRequest;
import com.lims.auth.dto.request.AdminRefreshTokenRequest;
import com.lims.auth.dto.response.AdminLoginResponse;
import com.lims.auth.dto.response.AdminMfaSetupResponse;
import com.lims.auth.dto.response.AdminTokenResponse;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.MfaException;
import com.lims.auth.exception.RateLimitException;
import com.lims.auth.service.AdminAuthenticationService;
import com.lims.auth.service.AdminMfaService;
import com.lims.auth.service.AdminTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
        issuer-uri: http://auth.lims.local/realms/lims-staff
        jwk-set-uri: http://auth.lims.local/realms/lims-staff/protocol/openid-connect/certs

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
        <mapstruct.version>1.6.3</mapstruct.version>
        <testcontainers.version>1.19.3</testcontainers.version>
        <springdoc.version>2.2.0</springdoc.version>
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
            <dependency>
                <groupId>org.testcontainers</groupId>
                <artifactId>testcontainers-bom</artifactId>
                <version>${testcontainers.version}</version>
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
            <artifactId>spring-boot-starter-data-redis</artifactId>
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
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-cache</artifactId>
        </dependency>

        <!-- Base de données -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- MapStruct pour mapping DTO/Entity -->
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

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Documentation OpenAPI/Swagger -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>${springdoc.version}</version>
        </dependency>

        <!-- JSON Processing -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>

        <!-- Monitoring -->
        <dependency>
            <groupId>io.micrometer</groupId>
            <artifactId>micrometer-registry-prometheus</artifactId>
        </dependency>

        <!-- Tests -->
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

        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>test</scope>
        </dependency>

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
                            <version>${mapstruct.version}</version>
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

            <!-- Plugin pour les tests d'intégration -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-failsafe-plugin</artifactId>
                <version>3.0.0-M9</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>integration-test</goal>
                            <goal>verify</goal>
                        </goals>
                    </execution>
                </executions>
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

# lims-patient-service/src/main/java/com/lims/patient/config/DatabaseConfig.java

```java
package com.lims.patient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Configuration de la base de données et de l'audit JPA
 */
@Configuration
@EnableJpaRepositories(basePackages = "com.lims.patient.repository")
public class DatabaseConfig {

    /**
     * Auditor pour JPA Auditing - utilise l'utilisateur connecté
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return Optional.of("SYSTEM");
            }
            return Optional.of(authentication.getName());
        };
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/MultiRealmJwtDecoder.java

```java
package com.lims.patient.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT personnalisé capable de gérer plusieurs realms Keycloak avec HMAC signing.
 *
 * Correction: Utilise SecretKeySpec pour HS512 au lieu de JWK Set URI qui est pour RSA.
 */
@Slf4j
public class MultiRealmJwtDecoder implements JwtDecoder {

    private final String keycloakBaseUrl;
    private final Map<String, JwtDecoder> realmDecoders;

    // Realms supportés
    private static final String LIMS_ADMIN_REALM = "lims-admin";
    private static final String LIMS_PATIENT_REALM = "lims-patient";
    private static final String LIMS_STAFF_REALM = "lims-staff";

    // Clés secrètes pour chaque realm
    private final String adminSecret;
    private final String patientSecret;
    private final String staffSecret;

    public MultiRealmJwtDecoder(String keycloakBaseUrl, String adminSecret, String patientSecret, String staffSecret) {
        this.keycloakBaseUrl = keycloakBaseUrl;
        this.adminSecret = adminSecret;
        this.patientSecret = patientSecret;
        this.staffSecret = staffSecret;
        this.realmDecoders = new HashMap<>();
        initializeRealmDecoders();
    }

    /**
     * Initialise les décodeurs pour chaque realm avec les bonnes clés HMAC
     */
    private void initializeRealmDecoders() {
        log.info("Initializing HMAC JWT decoders for multiple realms");

        try {
            // Configuration des clés secrètes pour HS512
            SecretKeySpec adminKey = new SecretKeySpec(
                    adminSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder adminDecoder = NimbusJwtDecoder.withSecretKey(adminKey).build();
            realmDecoders.put(LIMS_ADMIN_REALM, adminDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_ADMIN_REALM);

            SecretKeySpec patientKey = new SecretKeySpec(
                    patientSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder patientDecoder = NimbusJwtDecoder.withSecretKey(patientKey).build();
            realmDecoders.put(LIMS_PATIENT_REALM, patientDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_PATIENT_REALM);

            SecretKeySpec staffKey = new SecretKeySpec(
                    staffSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            JwtDecoder staffDecoder = NimbusJwtDecoder.withSecretKey(staffKey).build();
            realmDecoders.put(LIMS_STAFF_REALM, staffDecoder);
            log.info("Initialized HMAC JWT decoder for realm: {}", LIMS_STAFF_REALM);

        } catch (Exception e) {
            log.error("Failed to initialize HMAC JWT decoders for realms: {}", e.getMessage(), e);
            throw new IllegalStateException("Cannot initialize multi-realm JWT decoder", e);
        }
    }

    /**
     * Décode le JWT en déterminant automatiquement le realm approprié
     */
    @Override
    public Jwt decode(String token) throws JwtException {
        log.debug("Attempting to decode JWT token");

        // Essayer de décoder avec chaque realm jusqu'à ce qu'un fonctionne
        JwtException lastException = null;

        // Ordre de priorité des realms pour l'optimisation
        String[] realmOrder = {LIMS_ADMIN_REALM, LIMS_PATIENT_REALM, LIMS_STAFF_REALM};

        for (String realm : realmOrder) {
            try {
                JwtDecoder decoder = realmDecoders.get(realm);
                if (decoder != null) {
                    log.debug("Trying to decode JWT with realm: {}", realm);
                    Jwt jwt = decoder.decode(token);

                    // Vérifier que le realm dans le token correspond
                    String jwtRealm = jwt.getClaimAsString("realm");
                    if (realm.equals(jwtRealm)) {
                        log.debug("Successfully decoded JWT from realm: {} for subject: {}", realm, jwt.getSubject());
                        return jwt;
                    } else {
                        log.debug("JWT realm claim '{}' doesn't match expected realm '{}'", jwtRealm, realm);
                    }
                }
            } catch (JwtException e) {
                log.debug("Failed to decode JWT with realm {}: {}", realm, e.getMessage());
                lastException = e;
            }
        }

        // Si aucun décodeur n'a fonctionné, lancer la dernière exception
        String errorMessage = "Failed to decode JWT with any supported realm. Last error: " +
                (lastException != null ? lastException.getMessage() : "Unknown error");
        log.error(errorMessage);
        throw new JwtException(errorMessage, lastException);
    }

    /**
     * Méthode utilitaire pour obtenir les realms supportés
     */
    public String[] getSupportedRealms() {
        return realmDecoders.keySet().toArray(new String[0]);
    }

    /**
     * Méthode pour vérifier si un realm est supporté
     */
    public boolean isRealmSupported(String realm) {
        return realmDecoders.containsKey(realm);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/OpenApiConfig.java

```java
package com.lims.patient.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration OpenAPI/Swagger pour la documentation de l'API
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI patientServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LIMS Patient Service API")
                        .description("API de gestion des patients pour le système LIMS de laboratoire de biologie médicale")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Équipe LIMS")
                                .email("support@lims.com")
                                .url("https://lims.com"))
                        .license(new License()
                                .name("Propriétaire")
                                .url("https://lims.com/license")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8083")
                                .description("Serveur de développement"),
                        new Server()
                                .url("https://api.lims.com/patient")
                                .description("Serveur de production")))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Token JWT obtenu via Keycloak")));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/PatientAuditProperties.java

```java
package com.lims.patient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lims.patient.audit")
public class PatientAuditProperties {
    private Boolean enabled = true;
    private Boolean logAllAccess = true;
    private Integer retentionDays = 2555;
    private Boolean includeIpAddress = true;
    private Boolean includeUserAgent = true;
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/PatientBusinessProperties.java

```java
package com.lims.patient.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lims.patient.business-rules")
public class PatientBusinessProperties {
    private Integer maxContactsParType = 3;
    private Integer maxAdressesParType = 2;
    private Integer maxAssurancesParPatient = 5;
    private Boolean validationEmailObligatoire = true;
    private Boolean validationTelephoneObligatoire = false;
    private Integer dureeConservationAuditJours = 2555;
    private Boolean softDeleteUniquement = true;
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

import java.util.*;
import java.util.stream.Collectors;

/**
 * Convertisseur d'authentification JWT personnalisé pour le service Patient.
 *
 * Gère les tokens provenant de trois realms différents :
 * - lims-admin : Admins système (accès complet)
 * - lims-patient : Patients (accès à leurs propres données)
 * - lims-staff : Personnel laboratoire (accès selon laboratoire)
 */
@Slf4j
public class PatientJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter;

    public PatientJwtAuthenticationConverter() {
        this.defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // Configurer le converter pour extraire les authorities customisées
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    /**
     * Extrait les autorités depuis le JWT selon le realm d'origine
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        try {
            // Extraire les informations de base du JWT
            String realm = jwt.getClaimAsString("realm");
            String userType = jwt.getClaimAsString("user_type");
            String subject = jwt.getSubject();

            log.debug("Processing JWT from realm: {} for subject: {} with user_type: {}",
                    realm, subject, userType);

            // Traitement selon le realm
            return switch (realm) {
                case "lims-admin" -> extractAdminAuthorities(jwt);
                case "lims-patient" -> extractPatientAuthorities(jwt);
                case "lims-staff" -> extractStaffAuthorities(jwt);
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
     * Extrait les autorités pour un token admin (realm lims-admin)
     */
    private Collection<GrantedAuthority> extractAdminAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"ADMIN".equals(userType)) {
            log.warn("Invalid user_type for admin realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Ajouter le rôle de base ADMIN
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        // Extraire le rôle spécifique depuis le JWT
        String role = jwt.getClaimAsString("role");
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            log.debug("Added admin role: ROLE_{}", role);
        }

        // Extraire les permissions spécifiques
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        if (permissions != null) {
            for (String permission : permissions) {
                authorities.add(new SimpleGrantedAuthority("PERMISSION_" + permission));
                log.debug("Added admin permission: PERMISSION_{}", permission);
            }
        }

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Admin authorities granted: {}", authorities.size());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token patient (realm lims-patient)
     */
    private Collection<GrantedAuthority> extractPatientAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"PATIENT".equals(userType)) {
            log.warn("Invalid user_type for patient realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Les patients ont uniquement le rôle PATIENT
        authorities.add(new SimpleGrantedAuthority("ROLE_PATIENT"));

        // Ajouter des permissions spécifiques aux patients
        authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_OWN_DATA"));
        authorities.add(new SimpleGrantedAuthority("PERMISSION_UPDATE_OWN_CONTACT"));

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Patient authorities granted for subject {}: {}", jwt.getSubject(), authorities.size());
        return authorities;
    }

    /**
     * Extrait les autorités pour un token staff (realm lims-staff)
     */
    private Collection<GrantedAuthority> extractStaffAuthorities(Jwt jwt) {
        String userType = jwt.getClaimAsString("user_type");
        if (!"STAFF".equals(userType)) {
            log.warn("Invalid user_type for staff realm: {}", userType);
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>();

        // Ajouter le rôle de base STAFF
        authorities.add(new SimpleGrantedAuthority("ROLE_STAFF"));

        // Extraire le rôle spécifique du staff
        String role = jwt.getClaimAsString("role");
        if (role != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            log.debug("Added staff role: ROLE_{}", role);
        }

        // Ajouter des permissions spécifiques selon le rôle
        if (role != null) {
            switch (role) {
                case "ADMIN_LAB":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_ALL_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_WRITE_ALL_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_MANAGE_APPOINTMENTS"));
                    break;
                case "SECRETAIRE":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_SCHEDULE_APPOINTMENTS"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_UPDATE_PATIENT_CONTACT"));
                    break;
                case "PRELEVEUR", "TECHNICIEN":
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_VIEW_APPOINTMENTS"));
                    break;
                default:
                    authorities.add(new SimpleGrantedAuthority("PERMISSION_READ_PATIENTS_IN_LAB"));
            }
        }

        // Extraire les rôles Keycloak du realm
        Collection<GrantedAuthority> realmAuthorities = extractKeycloakRealmRoles(jwt);
        authorities.addAll(realmAuthorities);

        log.debug("Staff authorities granted for subject {}: {}", jwt.getSubject(), authorities.size());
        return authorities;
    }

    /**
     * Extrait les rôles Keycloak du realm depuis le token
     */
    private Collection<GrantedAuthority> extractKeycloakRealmRoles(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                @SuppressWarnings("unchecked")
                List<String> roles = (List<String>) realmAccess.get("roles");
                if (roles != null) {
                    return roles.stream()
                            .filter(role -> !role.startsWith("default-") && !role.equals("offline_access"))
                            .map(role -> new SimpleGrantedAuthority("KEYCLOAK_ROLE_" + role.toUpperCase()))
                            .collect(Collectors.toList());
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract Keycloak realm roles: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    /**
     * Extrait le nom du realm depuis l'issuer URI
     * Format attendu: http://localhost:8080/realms/lims-admin
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
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/PatientServiceConfig.java

```java
package com.lims.patient.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.cache.annotation.EnableCaching;

/**
 * Configuration principale du service Patient
 */
@Configuration
@EnableJpaAuditing
@EnableAsync
@EnableTransactionManagement
@EnableCaching
@RequiredArgsConstructor
public class PatientServiceConfig {

    /**
     * Configuration des propriétés métier patient
     */
    @Bean
    @ConfigurationProperties(prefix = "lims.patient.business-rules")
    public PatientBusinessProperties patientBusinessProperties() {
        return new PatientBusinessProperties();
    }

    /**
     * Configuration de l'audit
     */
    @Bean
    @ConfigurationProperties(prefix = "lims.patient.audit")
    public PatientAuditProperties patientAuditProperties() {
        return new PatientAuditProperties();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/RedisConfig.java

```java
package com.lims.patient.config;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

/**
 * Configuration Redis pour le cache des données patients
 */
@Configuration
@RequiredArgsConstructor
public class RedisConfig {

    /**
     * Template Redis pour les opérations manuelles
     */
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

    /**
     * Cache Manager pour Spring Cache
     */
    @Bean
    public CacheManager cacheManager(RedisConnectionFactory connectionFactory) {
        RedisCacheConfiguration cacheConfig = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(30)) // TTL par défaut 30 minutes
                .serializeKeysWith(org.springframework.data.redis.serializer.RedisSerializationContext.SerializationPair
                        .fromSerializer(new StringRedisSerializer()))
                .serializeValuesWith(org.springframework.data.redis.serializer.RedisSerializationContext.SerializationPair
                        .fromSerializer(new GenericJackson2JsonRedisSerializer()));

        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(cacheConfig)
                .transactionAware()
                .build();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/SecurityConfig.java

```java
package com.lims.patient.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Configuration de sécurité pour le service Patient avec support multi-realm JWT HMAC
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${security.oauth2.resourceserver.jwt.keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${lims.jwt.secrets.admin}")
    private String adminSecret;

    @Value("${lims.jwt.secrets.patient}")
    private String patientSecret;

    @Value("${lims.jwt.secrets.staff}")
    private String staffSecret;

    /**
     * Configuration de la chaîne de filtres de sécurité
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        log.info("Configuring security filter chain for Patient Service with multi-realm HMAC support");

        http
                // Désactiver CSRF pour les APIs REST
                .csrf(csrf -> csrf.disable())

                // Configuration CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Politique de session stateless
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configuration des autorisations
                .authorizeHttpRequests(authz -> authz
                        // Endpoints publics
                        .requestMatchers(
                                "/actuator/**",
                                "/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**"
                        ).permitAll()

                        // Endpoints API - nécessitent une authentification
                        .requestMatchers("/api/v1/**").authenticated()

                        // Tout le reste nécessite une authentification
                        .anyRequest().authenticated()
                )

                // Configuration OAuth2 Resource Server avec JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );

        return http.build();
    }

    /**
     * Décodeur JWT configuré pour supporter plusieurs realms Keycloak avec HMAC
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("Using simple JJWT decoder that works in debug");
        return new SimpleHmacJwtDecoder(adminSecret);
    }

    /**
     * Convertisseur d'authentification JWT personnalisé pour multi-realms
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new PatientJwtAuthenticationConverter();
    }

    /**
     * Configuration CORS
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Origines autorisées (en développement, ajuster pour la production)
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Méthodes HTTP autorisées
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));

        // Headers autorisés
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "Accept", "X-Requested-With",
                "Cache-Control", "X-Laboratory-Id", "X-Patient-Id"
        ));

        // Headers exposés dans la réponse
        configuration.setExposedHeaders(Arrays.asList(
                "X-Total-Count", "X-Page-Number", "X-Page-Size"
        ));

        // Autoriser les credentials
        configuration.setAllowCredentials(true);

        // Durée de cache pour les requêtes preflight
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/SimpleHmacJwtDecoder.java

```java
package com.lims.patient.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT simple utilisant directement JJWT (même lib que le service auth)
 */
@Slf4j
public class SimpleHmacJwtDecoder implements JwtDecoder {

    private final String jwtSecret;

    public SimpleHmacJwtDecoder(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            log.debug("Decoding JWT token with JJWT library");

            // Utiliser directement la clé brute (comme dans le debug qui marche)
            SecretKeySpec secretKey = new SecretKeySpec(
                    jwtSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );
            log.debug("Using raw string secret key");

            // Décoder avec JJWT
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("Successfully decoded JWT for subject: {}", claims.getSubject());

            // Vérifier que c'est un token admin pour ce service
            String realm = (String) claims.get("realm");
            if (!"lims-admin".equals(realm)) {
                log.debug("Token is not for admin realm: {}", realm);
                // Pour l'instant on accepte tous les realms, mais on pourrait filtrer ici
            }

            // Convertir en Spring Security Jwt
            return createSpringJwt(token, claims);

        } catch (Exception e) {
            log.error("Failed to decode JWT: {}", e.getMessage());
            throw new JwtException("Failed to decode JWT", e);
        }
    }

    private Jwt createSpringJwt(String token, Claims claims) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS512");
        headers.put("typ", "JWT");

        Map<String, Object> claimsMap = new HashMap<>(claims);

        Instant issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : Instant.now();
        Instant expiresAt = claims.getExpiration() != null ? claims.getExpiration().toInstant() : Instant.now().plusSeconds(3600);

        return new Jwt(
                token,
                issuedAt,
                expiresAt,
                headers,
                claimsMap
        );
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/config/ValidationConfig.java

```java
package com.lims.patient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;

/**
 * Configuration pour la validation des données
 */
@Configuration
public class ValidationConfig {

    @Bean
    public LocalValidatorFactoryBean validator() {
        return new LocalValidatorFactoryBean();
    }

    @Bean
    public MethodValidationPostProcessor methodValidationPostProcessor() {
        MethodValidationPostProcessor processor = new MethodValidationPostProcessor();
        processor.setValidator(validator());
        return processor;
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

# lims-patient-service/src/main/java/com/lims/patient/controller/PatientController.java

```java

package com.lims.patient.controller;

import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.service.PatientService;
import com.lims.patient.service.PatientSearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des patients - Version centralisée corrigée
 */
@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Patients", description = "API de gestion des patients")
public class PatientController {

    private final PatientService patientService;
    private final PatientSearchService patientSearchService;

    // ============================================
    // ENDPOINTS CRUD
    // ============================================

    /**
     * Créer un nouveau patient
     */
    @PostMapping
    @Operation(summary = "Créer un nouveau patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Patient créé avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides"),
            @ApiResponse(responseCode = "409", description = "Patient déjà existant")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> createPatient(
            @Valid @RequestBody CreatePatientRequest request) {

        log.info("Création d'un nouveau patient: {} {}",
                request.personalInfo().prenom(), request.personalInfo().nom());

        PatientResponse response = patientService.createPatient(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Récupérer un patient par ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Récupérer un patient par ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Patient trouvé"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN') or hasRole('PATIENT')")
    public ResponseEntity<PatientResponse> getPatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id) {

        log.info("Récupération du patient: {}", id);

        PatientResponse response = patientService.getPatient(id);

        return ResponseEntity.ok(response);
    }

    /**
     * Mettre à jour un patient
     */
    @PutMapping("/{id}")
    @Operation(summary = "Mettre à jour un patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Patient mis à jour"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> updatePatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id,
            @Valid @RequestBody UpdatePatientRequest request) {

        log.info("Mise à jour du patient: {}", id);

        PatientResponse response = patientService.updatePatient(id, request);

        return ResponseEntity.ok(response);
    }

    /**
     * Supprimer un patient (soft delete)
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer un patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Patient supprimé"),
            @ApiResponse(responseCode = "404", description = "Patient non trouvé")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deletePatient(
            @Parameter(description = "ID du patient") @PathVariable(value = "id") UUID id) {

        log.info("Suppression du patient: {}", id);

        patientService.deletePatient(id);

        return ResponseEntity.noContent().build();
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE
    // ============================================

    /**
     * Recherche multicritères de patients (POST recommandé)
     */
    @PostMapping("/search")
    @Operation(summary = "Recherche multicritères de patients")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche"),
            @ApiResponse(responseCode = "400", description = "Critères de recherche invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSearchResponse> searchPatients(
            @Valid @RequestBody PatientSearchRequest request) {

        log.info("Recherche de patients avec critères: {}", request);

        PatientSearchResponse response = patientService.searchPatients(request);

        return ResponseEntity.ok(response);
    }

    /**
     * Recherche simple par un seul critère (GET acceptable)
     */
    @GetMapping("/search/simple")
    @Operation(summary = "Recherche simple par un critère")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche simple")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> simpleSearch(
            @Parameter(description = "Type de recherche")
            @RequestParam(value = "type") String type,

            @Parameter(description = "Valeur recherchée")
            @RequestParam(value = "value") String value,

            @Parameter(description = "Limite de résultats")
            @RequestParam(value = "limit", defaultValue = "20") int limit) {

        log.info("Recherche simple: {} = {}", type, value);

        List<PatientSummaryResponse> results = switch (type.toLowerCase()) {
            case "nom" -> patientSearchService.searchByNomPrenom(value, null);
            case "prenom" -> patientSearchService.searchByNomPrenom(null, value);
            // case "ville" -> patientSearchService.searchByVille(value);
            // case "medecin" -> patientSearchService.searchByMedecinTraitant(value);
            default -> throw new IllegalArgumentException("Type de recherche non supporté: " + type);
        };

        return ResponseEntity.ok(results.stream().limit(limit).toList());
    }

    /**
     * Recherche rapide (typeahead) - GET acceptable car simple
     */
    @GetMapping("/search/quick")
    @Operation(summary = "Recherche rapide de patients")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche rapide")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> quickSearch(
            @Parameter(description = "Terme de recherche")
            @RequestParam(value = "query") String query,
            @Parameter(description = "Limite de résultats")
            @RequestParam(value = "limit", defaultValue = "10") int limit) {

        log.info("Recherche rapide: {}", query);

        List<PatientSummaryResponse> results = patientSearchService.quickSearch(query, limit);

        return ResponseEntity.ok(results);
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE SPÉCIFIQUES
    // ============================================

    /**
     * Recherche par email
     */
    @GetMapping("/search/email")
    @Operation(summary = "Recherche par email")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByEmail(
            @Parameter(description = "Email du patient")
            @RequestParam(value = "email") String email) {

        log.info("Recherche par email: {}", email);

        Optional<PatientResponse> patient = patientService.findByEmail(email);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par téléphone
     */
    @GetMapping("/search/telephone")
    @Operation(summary = "Recherche par téléphone")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByTelephone(
            @Parameter(description = "Téléphone du patient")
            @RequestParam(value = "telephone") String telephone) {

        log.info("Recherche par téléphone: {}", telephone);

        Optional<PatientResponse> patient = patientService.findByTelephone(telephone);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    @GetMapping("/search/nir")
    @Operation(summary = "Recherche par numéro de sécurité sociale")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> findByNumeroSecu(
            @Parameter(description = "Numéro de sécurité sociale")
            @RequestParam(value = "numeroSecu") String numeroSecu) {

        log.info("Recherche par numéro de sécurité sociale");

        Optional<PatientResponse> patient = patientService.findByNumeroSecu(numeroSecu);

        return patient.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Recherche par ville
     */
    @GetMapping("/search/ville")
    @Operation(summary = "Recherche par ville")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> findByVille(
            @Parameter(description = "Ville")
            @RequestParam(value = "ville") String ville) {

        log.info("Recherche par ville: {}", ville);

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchByVille(ville);

        return ResponseEntity.ok(patients);
    }

    /**
     * Recherche par médecin traitant
     */
    @GetMapping("/search/medecin")
    @Operation(summary = "Recherche par médecin traitant")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> findByMedecinTraitant(
            @Parameter(description = "Médecin traitant")
            @RequestParam(value = "medecin") String medecin) {

        log.info("Recherche par médecin traitant: {}", medecin);

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchByMedecinTraitant(medecin);

        return ResponseEntity.ok(patients);
    }

    // ============================================
    // ENDPOINTS DE LISTE
    // ============================================

    /**
     * Liste des patients actifs
     */
    @GetMapping("/active")
    @Operation(summary = "Liste des patients actifs")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> getActivePatients(
            @Parameter(description = "Numéro de page")
            @RequestParam(value = "page", defaultValue = "0") int page,
            @Parameter(description = "Taille de la page")
            @RequestParam(value = "size", defaultValue = "20") int size) {

        log.info("Récupération des patients actifs");

        List<PatientSummaryResponse> patients = patientService.getActivePatients(page, size);

        return ResponseEntity.ok(patients);
    }

    /**
     * Liste des patients avec notifications
     */
    @GetMapping("/notifications")
    @Operation(summary = "Liste des patients avec notifications activées")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> getPatientsWithNotifications() {

        log.info("Récupération des patients avec notifications");

        List<PatientSummaryResponse> patients = List.of(); // patientSearchService.searchPatientsWithNotifications();

        return ResponseEntity.ok(patients);
    }

    /**
     * Statistiques des patients
     */
    @GetMapping("/stats")
    @Operation(summary = "Statistiques des patients")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientStatsResponse> getPatientStats() {

        log.info("Récupération des statistiques patients");

        PatientStatsResponse stats = PatientStatsResponse.builder()
                .totalPatientsActifs(patientSearchService.countActivePatients())
                .statistiquesParStatut(patientSearchService.getPatientStatisticsByStatus())
                .statistiquesParSexe(patientSearchService.getPatientStatisticsByGender())
                .statistiquesParVille(patientSearchService.getPatientStatisticsByCity())
                .build();

        return ResponseEntity.ok(stats);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/debug/JwtDebugTool.java

```java
package com.lims.patient.debug;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Outil de debug pour tester le décodage JWT
 * À supprimer après résolution du problème
 */
@Slf4j
public class JwtDebugTool {

    public static void debugJwtDecoding() {
        String token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzdXBlci1hZG1pbi1kZXYtMDAxIiwidXNlcl90eXBlIjoiQURNSU4iLCJyb2xlIjoiU1VQRVJfQURNSU4iLCJtZmFfdmVyaWZpZWQiOnRydWUsInBlcm1pc3Npb25zIjpbIkFVRElUX1JFQUQiLCJDT05GSUdVUkFUSU9OX1dSSVRFIiwiU1lTVEVNX0FETUlOIiwiVVNFUl9NQU5BR0VNRU5UIl0sInNlc3Npb25faWQiOiIwMjZiNjEyOS03YzZjLTRkZjctOGM1YS02ZWJjMzc5OGY2M2UiLCJyZWFsbSI6ImxpbXMtYWRtaW4iLCJleHAiOjE3NTIwOTc3NDUsImlhdCI6MTc1MjA5NDE0NSwiZW1haWwiOiJzdXBlcmFkbWluQGxpbXMubG9jYWwiLCJpc3MiOiJsaW1zLWF1dGgtc2VydmljZSJ9.MawaHKIVh1Z3Uw8q7EQ-2MMnBYiSNtxEjIc-qELyk1TDtfceymHfGFsQz8_hpTO2PG9Mr9d9WtP8AhBYzFr6vw";
        String secret = "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU=";

        log.info("=== JWT DEBUG TOOL ===");
        log.info("Testing JWT decoding with different key formats");

        // Test 1: Base64 décodage
        try {
            byte[] keyBytes = Base64.getDecoder().decode(secret);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.info("✅ SUCCESS with Base64 decoded key!");
            log.info("Subject: {}", claims.getSubject());
            log.info("Realm: {}", claims.get("realm"));
            log.info("User type: {}", claims.get("user_type"));
            return;
        } catch (Exception e) {
            log.error("❌ Base64 decoding failed: {}", e.getMessage());
        }

        // Test 2: Clé brute
        try {
            SecretKeySpec secretKey = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.info("✅ SUCCESS with raw string key!");
            log.info("Subject: {}", claims.getSubject());
            log.info("Realm: {}", claims.get("realm"));
            log.info("User type: {}", claims.get("user_type"));
        } catch (Exception e) {
            log.error("❌ Raw string decoding failed: {}", e.getMessage());
        }

        // Test 3: Informations sur la clé
        try {
            log.info("Secret key length: {} characters", secret.length());
            log.info("Secret key (first 50 chars): {}", secret.substring(0, Math.min(50, secret.length())));

            if (isBase64(secret)) {
                byte[] decoded = Base64.getDecoder().decode(secret);
                log.info("Base64 decoded length: {} bytes", decoded.length);
            } else {
                log.info("Secret is not valid Base64");
            }
        } catch (Exception e) {
            log.error("Error analyzing secret: {}", e.getMessage());
        }
    }

    private static boolean isBase64(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/config/PatientBusinessRules.java

```java
package com.lims.patient.dto.config;

import lombok.Builder;

/**
 * DTO pour la configuration des règles métier patient
 */
@Builder
public record PatientBusinessRules(
        Integer maxContactsParType,
        Integer maxAdressesParType,
        Integer maxAssurancesParPatient,
        Boolean validationEmailObligatoire,
        Boolean validationTelephoneObligatoire,
        Integer dureeConservationAuditJours,
        Boolean softDeleteUniquement
) {
    // Valeurs par défaut
    public static PatientBusinessRules defaults() {
        return PatientBusinessRules.builder()
                .maxContactsParType(3)
                .maxAdressesParType(2)
                .maxAssurancesParPatient(5)
                .validationEmailObligatoire(true)
                .validationTelephoneObligatoire(false)
                .dureeConservationAuditJours(2555) // 7 ans
                .softDeleteUniquement(true)
                .build();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/error/ErrorResponse.java

```java
package com.lims.patient.dto.error;

import lombok.Builder;
import java.time.LocalDateTime;
import java.util.List;

@Builder
public record ErrorResponse(
        String code,
        String message,
        String detail,
        LocalDateTime timestamp,
        String path,
        List<FieldError> fieldErrors
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/error/FieldError.java

```java
package com.lims.patient.dto.error;

import lombok.Builder;

@Builder
public record FieldError(
        String field,
        Object rejectedValue,
        String message
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/PageInfo.java

```java
package com.lims.patient.dto;

import lombok.Builder;

@Builder
public record PageInfo(
        Integer currentPage,
        Integer totalPages,
        Integer pageSize,
        Long totalElements,
        Boolean hasNext,
        Boolean hasPrevious
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/AddressRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.AddressType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour une adresse postale
 */
@Builder
public record AddressRequest(
        @NotNull
        AddressType typeAdresse,

        @NotBlank @Size(max = 255)
        String ligne1,

        @Size(max = 255)
        String ligne2,

        @NotBlank @Size(min = 5, max = 10)
        String codePostal,

        @NotBlank @Size(max = 100)
        String ville,

        @Size(max = 100)
        String departement,

        @Size(max = 100)
        String region,

        @NotBlank @Size(max = 50)
        String pays,

        @NotNull
        Boolean estPrincipale
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/ConsentRequest.java

```java
package com.lims.patient.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;

/**
 * DTO pour les consentements RGPD
 */
@Builder
public record ConsentRequest(
        @NotNull
        Boolean consentementCreationCompte,

        @NotNull
        Boolean consentementSms,

        @NotNull
        Boolean consentementEmail
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/ConsentUpdateRequest.java

```java
package com.lims.patient.dto.request;

import lombok.Builder;

/**
 * DTO pour la mise à jour des consentements
 */
@Builder
public record ConsentUpdateRequest(
        Boolean consentementSms,
        Boolean consentementEmail
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/ContactInfoRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.math.BigDecimal;

/**
 * DTO pour les informations de contact centralisées
 */
@Builder
public record ContactInfoRequest(
        @NotBlank @Email @Size(max = 255)
        String email,

        @NotBlank @Pattern(regexp = "^\\+[1-9][0-9]{8,14}$", message = "Format téléphone invalide")
        String telephone,

        @NotBlank @Size(max = 255)
        String adresseLigne1,

        @Size(max = 255)
        String adresseLigne2,

        @NotBlank @Pattern(regexp = "^[0-9]{5}$", message = "Code postal invalide")
        String codePostal,

        @NotBlank @Size(max = 100)
        String ville,

        @Size(max = 100)
        String departement,

        @Size(max = 100)
        String region,

        @Size(max = 100)
        String pays,

        BigDecimal latitude,

        BigDecimal longitude,

        DeliveryMethod methodeLivraisonPreferee,

        NotificationPreference preferenceNotification,

        @Size(max = 5)
        String languePreferee,

        Boolean notificationsResultats,

        Boolean notificationsRdv,

        Boolean notificationsRappels
) {}


```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/ContactInfoUpdateRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.math.BigDecimal;

/**
 * DTO pour la mise à jour des informations de contact
 */
@Builder
public record ContactInfoUpdateRequest(
        @Email @Size(max = 255)
        String email,

        @Pattern(regexp = "^\\+[1-9][0-9]{8,14}$", message = "Format téléphone invalide")
        String telephone,

        @Size(max = 255)
        String adresseLigne1,

        @Size(max = 255)
        String adresseLigne2,

        @Pattern(regexp = "^[0-9]{5}$", message = "Code postal invalide")
        String codePostal,

        @Size(max = 100)
        String ville,

        @Size(max = 100)
        String departement,

        @Size(max = 100)
        String region,

        @Size(max = 100)
        String pays,

        BigDecimal latitude,

        BigDecimal longitude,

        DeliveryMethod methodeLivraisonPreferee,

        NotificationPreference preferenceNotification,

        @Size(max = 5)
        String languePreferee,

        Boolean notificationsResultats,

        Boolean notificationsRdv,

        Boolean notificationsRappels
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/CreatePatientRequest.java

```java
// ============================================
// DTOs pour la création de patients (version centralisée)
// ============================================

package com.lims.patient.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.util.List;

/**
 * DTO principal pour la création d'un patient - Version centralisée
 */
@Builder
public record CreatePatientRequest(
        @Valid @NotNull
        PersonalInfoRequest personalInfo,

        @Valid @NotNull
        ContactInfoRequest contactInfo,

        @Valid
        List<InsuranceRequest> insurances,

        @Valid @NotNull
        ConsentRequest consent,

        String createdBy // ID du staff qui crée le patient
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/EmailContactRequest.java

```java
package com.lims.patient.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour une adresse email
 */
@Builder
public record EmailContactRequest(
        @NotBlank @Email(message = "Format email invalide")
        @Size(max = 255)
        String adresseEmail,

        @NotNull
        Boolean estPrincipal,

        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/InsuranceRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.InsuranceType;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * DTO pour une assurance
 */
@Builder
public record InsuranceRequest(
        @NotNull
        InsuranceType typeAssurance,

        @NotBlank @Size(max = 255)
        String nomOrganisme,

        @NotBlank @Size(max = 100)
        String numeroAdherent,

        @NotNull
        LocalDate dateDebut,

        LocalDate dateFin,

        Boolean tiersPayantAutorise,

        @DecimalMin("0.00") @DecimalMax("100.00")
        BigDecimal pourcentagePriseCharge,

        @Size(max = 500)
        String referenceDocument
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/PatientSearchRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la recherche de patients
 */
@Builder
public record PatientSearchRequest(
        String nom,
        String prenom,
        String numeroSecu,
        String email,
        String telephone,
        String ville,
        String codePostal,
        LocalDate dateNaissance,
        GenderType sexe,
        PatientStatus statut,
        int page,
        int size,
        String sortBy,
        String sortDirection
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/PersonalInfoRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import com.lims.patient.validation.ValidNIR;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour les informations personnelles du patient
 */
@Builder
public record PersonalInfoRequest(
        @NotBlank @Size(max = 100)
        String nom,

        @NotBlank @Size(max = 100)
        String prenom,

        @Size(max = 100)
        String nomJeuneFille,

        @NotNull @Past
        LocalDate dateNaissance,

        @Size(max = 100)
        String lieuNaissance,

        @NotNull
        GenderType sexe,

        @NotBlank @Pattern(regexp = "^[12][0-9]{12}[0-9]{2}$", message = "Format NIR invalide")
        String numeroSecu,

        @Size(max = 255)
        String medecinTraitant,

        String allergiesConnues,

        String antecedentsMedicaux
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/PersonalInfoUpdateRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.GenderType;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la mise à jour des informations personnelles
 */
@Builder
public record PersonalInfoUpdateRequest(
        @Size(max = 100)
        String nom,

        @Size(max = 100)
        String prenom,

        @Size(max = 100)
        String nomJeuneFille,

        @Past
        LocalDate dateNaissance,

        @Size(max = 100)
        String lieuNaissance,

        GenderType sexe,

        @Size(max = 255)
        String medecinTraitant,

        String allergiesConnues,

        String antecedentsMedicaux
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/PhoneContactRequest.java

```java
package com.lims.patient.dto.request;

import com.lims.patient.enums.ContactType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

/**
 * DTO pour un contact téléphonique
 */
@Builder
public record PhoneContactRequest(
        @NotNull
        ContactType typeContact,

        @NotBlank @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$", message = "Format téléphone invalide (+33...)")
        String numeroTelephone,

        @Pattern(regexp = "^\\+[1-9][0-9]{0,4}$")
        String indicatifPays,

        @Size(max = 10)
        String extension,

        @NotNull
        Boolean estPrincipal,

        // Si c'est un contact d'urgence
        @Size(max = 100)
        String nomContactUrgence,

        @Size(max = 50)
        String relationContact
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/UpdatePatientRequest.java

```java
package com.lims.patient.dto.request;

import lombok.Builder;

import java.util.List;

/**
 * DTO pour la mise à jour d'un patient
 */
@Builder
public record UpdatePatientRequest(
        PersonalInfoUpdateRequest personalInfo,
        ContactInfoUpdateRequest contactInfo,
        List<InsuranceRequest> insurances,
        ConsentUpdateRequest consent
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/AddressResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.AddressType;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record AddressResponse(
        String id,
        AddressType typeAdresse,
        String ligne1,
        String ligne2,
        String codePostal,
        String ville,
        String departement,
        String region,
        String pays,
        Boolean estPrincipale,
        Boolean estValide,
        LocalDateTime dateValidation
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/AuditLogResponse.java

```java
package com.lims.patient.dto.response;

import java.time.LocalDateTime;

/**
 * DTO de réponse pour les logs d'audit
 */
public record AuditLogResponse(
        Long id,
        String patientId,
        String action,
        String description,
        String tableConcernee,
        String idEnregistrement,
        String performedBy,
        String performedByType,
        String realmUtilisateur,
        String clientIp,
        String userAgent,
        String sessionId,
        String anciennesValeurs,
        String nouvellesValeurs,
        String result,
        String messageErreur,
        LocalDateTime dateAction,
        String correlationId
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/ConsentResponse.java

```java
package com.lims.patient.dto.response;

import lombok.Builder;

import java.time.LocalDateTime;

/**
 * DTO de réponse pour les consentements
 */
@Builder
public record ConsentResponse(
        Boolean consentementCreationCompte,
        Boolean consentementSms,
        Boolean consentementEmail,
        LocalDateTime dateConsentement
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/ContactInfoResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
import lombok.Builder;

import java.math.BigDecimal;

/**
 * DTO de réponse pour les informations de contact
 */
@Builder
public record ContactInfoResponse(
        String email,
        String telephone,
        String adresseComplete,
        String adresseLigne1,
        String adresseLigne2,
        String codePostal,
        String ville,
        String departement,
        String region,
        String pays,
        BigDecimal latitude,
        BigDecimal longitude,
        DeliveryMethod methodeLivraisonPreferee,
        NotificationPreference preferenceNotification,
        String languePreferee,
        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/EmailContactResponse.java

```java
package com.lims.patient.dto.response;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record EmailContactResponse(
        String id,
        String adresseEmail,
        Boolean estPrincipal,
        Boolean estValide,
        LocalDateTime dateValidation,
        Boolean notificationsResultats,
        Boolean notificationsRdv,
        Boolean notificationsRappels
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/InsuranceResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.InsuranceType;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * DTO de réponse pour une assurance
 */
@Builder
public record InsuranceResponse(
        String id,
        InsuranceType typeAssurance,
        String nomOrganisme,
        String numeroAdherent,
        LocalDate dateDebut,
        LocalDate dateFin,
        Boolean estActive,
        Boolean tiersPayantAutorise,
        BigDecimal pourcentagePriseCharge,
        String referenceDocument
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/MetadataResponse.java

```java
package com.lims.patient.dto.response;


import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDateTime;

/**
 * DTO de réponse pour les métadonnées
 */
@Builder
public record MetadataResponse(
        PatientStatus statut,
        LocalDateTime dateCreation,
        LocalDateTime dateModification,
        String creePar,
        String modifiePar,
        Boolean actif
) {}


```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PatientResponse.java

```java
package com.lims.patient.dto.response;

import lombok.Builder;

import java.util.List;

/**
 * DTO de réponse pour un patient complet
 */
@Builder
public record PatientResponse(
        String id,
        PersonalInfoResponse personalInfo,
        ContactInfoResponse contactInfo,
        List<InsuranceResponse> insurances,
        ConsentResponse consent,
        MetadataResponse metadata
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PatientSearchResponse.java

```java
package com.lims.patient.dto.response;

import lombok.Builder;

import java.util.List;

/**
 * DTO de réponse pour la recherche
 */
@Builder
public record PatientSearchResponse(
        List<PatientSummaryResponse> patients,
        int currentPage,
        int totalPages,
        long totalElements,
        int pageSize
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PatientStatsResponse.java

```java
package com.lims.patient.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO pour les statistiques des patients
 */
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PatientStatsResponse {
    private long totalPatientsActifs;
    private List<Object[]> statistiquesParStatut;
    private List<Object[]> statistiquesParSexe;
    private List<Object[]> statistiquesParVille;
}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PatientSummaryResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * DTO résumé pour la liste des patients
 */
@Builder
public record PatientSummaryResponse(
        String id,
        String nomComplet,
        String email,
        String telephone,
        LocalDate dateNaissance,
        Integer age,
        GenderType sexe,
        String ville,
        PatientStatus statut,
        LocalDateTime dateCreation
) {}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PersonalInfoResponse.java

```java
package com.lims.patient.dto.response;

// import com.lims.patient.dto.request.GenderType;
import com.lims.patient.enums.GenderType;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO de réponse pour les informations personnelles
 */
@Builder
public record PersonalInfoResponse(
        String nom,
        String prenom,
        String nomJeuneFille,
        LocalDate dateNaissance,
        String lieuNaissance,
        GenderType sexe,
        String numeroSecuMasque,
        Integer age,
        String medecinTraitant,
        String allergiesConnues,
        String antecedentsMedicaux
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PhoneContactResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.ContactType;
import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public record PhoneContactResponse(
        String id,
        ContactType typeContact,
        String numeroTelephone,
        String indicatifPays,
        String extension,
        Boolean estPrincipal,
        Boolean estValide,
        LocalDateTime dateValidation,
        String nomContactUrgence,
        String relationContact
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PrescriptionSummaryResponse.java

```java
package com.lims.patient.dto.response;

import com.lims.patient.enums.PrescriptionStatus;
import lombok.Builder;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Builder
public record PrescriptionSummaryResponse(
        String id,
        String nomMedecin,
        String rppsMedecin,
        LocalDate datePrescription,
        PrescriptionStatus statut,
        Boolean estRenouvelable,
        LocalDate renouvelableJusqu,
        Integer nombreAnalyses,
        LocalDateTime dateCreation
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/dto/SearchStats.java

```java
package com.lims.patient.dto;

import lombok.Builder;

@Builder
public record SearchStats(
        Long totalPatients,
        Long patientsActifs,
        Long patientsAvecAssurance,
        Long patientsAvecOrdonnance,
        Long nouveauxPatientsMoisCourant
) {}

```

# lims-patient-service/src/main/java/com/lims/patient/entity/Ordonnance.java

```java
package com.lims.patient.entity;

import com.lims.patient.enums.PrescriptionStatus;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité Ordonnance
 */
@Entity
@Table(name = "ordonnances", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Ordonnance {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Column(name = "nom_medecin", nullable = false)
    private String nomMedecin;

    @Column(name = "rpps_medecin", length = 20)
    private String rppsMedecin;

    @Column(name = "date_prescription", nullable = false)
    private LocalDate datePrescription;

    @Enumerated(EnumType.STRING)
    @Column(name = "statut")
    private PrescriptionStatus statut = PrescriptionStatus.EN_ATTENTE;

    @Column(name = "reference_document", length = 500)
    private String referenceDocument; // Clé MinIO

    @Column(name = "texte_extrait", columnDefinition = "TEXT")
    private String texteExtrait;

    @Column(name = "confidence_ocr", precision = 5, scale = 2)
    private BigDecimal confidenceOcr;

    @Column(name = "est_renouvelable", nullable = false)
    private Boolean estRenouvelable = false;

    @Column(name = "renouvelable_jusqu")
    private LocalDate renouvelableJusqu;

    @Column(name = "nombre_renouvellements")
    private Integer nombreRenouvellements = 0;

    @Column(name = "validee_par", length = 100)
    private String valideePar;

    @Column(name = "date_validation")
    private LocalDateTime dateValidation;

    @Column(name = "commentaire_validation", columnDefinition = "TEXT")
    private String commentaireValidation;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @Column(name = "date_suppression")
    private LocalDateTime dateSuppression; // Soft delete

    @OneToMany(mappedBy = "ordonnance", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<OrdonnanceAnalyse> analyses = new ArrayList<>();

    /**
     * Vérifie si l'ordonnance est encore valide pour renouvellement
     */
    public boolean canBeRenewed() {
        return estRenouvelable &&
                renouvelableJusqu != null &&
                !LocalDate.now().isAfter(renouvelableJusqu) &&
                dateSuppression == null;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/entity/OrdonnanceAnalyse.java

```java
package com.lims.patient.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Analyse demandée dans une ordonnance
 */
@Entity
@Table(name = "ordonnance_analyses", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OrdonnanceAnalyse {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ordonnance_id", nullable = false)
    private Ordonnance ordonnance;

    @Column(name = "code_analyse", nullable = false, length = 20)
    private String codeAnalyse;

    @Column(name = "libelle_analyse", nullable = false)
    private String libelleAnalyse;

    @Column(name = "est_urgent", nullable = false)
    private Boolean estUrgent = false;

    @Column(name = "commentaire", columnDefinition = "TEXT")
    private String commentaire;

    @Column(name = "extrait_automatiquement")
    private Boolean extraitAutomatiquement = false;

    @Column(name = "confidence_extraction", precision = 5, scale = 2)
    private BigDecimal confidenceExtraction;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;
}

```

# lims-patient-service/src/main/java/com/lims/patient/entity/Patient.java

```java
package com.lims.patient.entity;

import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.NotificationPreference;
import com.lims.patient.enums.PatientStatus;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Entité principale Patient - Version centralisée
 * Contient les données civiles obligatoires et les informations de contact centralisées
 */
@Entity
@Table(name = "patients", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Patient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // ===== IDENTIFICATION CIVILE =====
    @Column(name = "nom", nullable = false, length = 100)
    private String nom;

    @Column(name = "prenom", nullable = false, length = 100)
    private String prenom;

    @Column(name = "nom_jeune_fille", length = 100)
    private String nomJeuneFille;

    @Column(name = "date_naissance", nullable = false)
    private LocalDate dateNaissance;

    @Column(name = "lieu_naissance", length = 100)
    private String lieuNaissance;

    @Enumerated(EnumType.STRING)
    @Column(name = "sexe", nullable = false)
    private GenderType sexe = GenderType.NON_PRECISE;

    @Column(name = "numero_secu", nullable = false, unique = true, length = 15)
    private String numeroSecu;

    // ===== CONTACT CENTRALISÉ =====
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "telephone", nullable = false, unique = true, length = 20)
    private String telephone;

    // ===== ADRESSE CENTRALISÉE =====
    @Column(name = "adresse_ligne1", nullable = false)
    private String adresseLigne1;

    @Column(name = "adresse_ligne2")
    private String adresseLigne2;

    @Column(name = "code_postal", nullable = false, length = 10)
    private String codePostal;

    @Column(name = "ville", nullable = false, length = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    private String departement;

    @Column(name = "region", length = 100)
    private String region;

    @Column(name = "pays", nullable = false, length = 100)
    private String pays = "France";

    @Column(name = "latitude", columnDefinition = "DECIMAL(10,8)")
    private BigDecimal latitude;

    @Column(name = "longitude", columnDefinition = "DECIMAL(11,8)")
    private BigDecimal longitude;

    // ===== PRÉFÉRENCES COMMUNICATION =====
    @Enumerated(EnumType.STRING)
    @Column(name = "methode_livraison_preferee")
    private DeliveryMethod methodeLivraisonPreferee = DeliveryMethod.EMAIL;

    @Enumerated(EnumType.STRING)
    @Column(name = "preference_notification")
    private NotificationPreference preferenceNotification = NotificationPreference.TOUS;

    @Column(name = "langue_preferee", length = 5)
    private String languePreferee = "fr-FR";

    // ===== PRÉFÉRENCES NOTIFICATIONS =====
    @Column(name = "notifications_resultats")
    private Boolean notificationsResultats = true;

    @Column(name = "notifications_rdv")
    private Boolean notificationsRdv = true;

    @Column(name = "notifications_rappels")
    private Boolean notificationsRappels = true;

    // ===== DONNÉES MÉDICALES =====
    @Column(name = "medecin_traitant")
    private String medecinTraitant;

    @Column(name = "allergies_connues", columnDefinition = "TEXT")
    private String allergiesConnues;

    @Column(name = "antecedents_medicaux", columnDefinition = "TEXT")
    private String antecedentsMedicaux;

    // ===== CONSENTEMENTS RGPD =====
    @Column(name = "consentement_creation_compte", nullable = false)
    private Boolean consentementCreationCompte = false;

    @Column(name = "consentement_sms", nullable = false)
    private Boolean consentementSms = false;

    @Column(name = "consentement_email", nullable = false)
    private Boolean consentementEmail = false;

    @Column(name = "date_consentement")
    private LocalDateTime dateConsentement;

    // ===== MÉTADONNÉES SYSTÈME =====
    @Enumerated(EnumType.STRING)
    @Column(name = "statut", nullable = false)
    private PatientStatus statut = PatientStatus.ACTIF;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @CreatedBy
    @Column(name = "cree_par", nullable = false, updatable = false, length = 100)
    private String creePar;

    @LastModifiedBy
    @Column(name = "modifie_par", length = 100)
    private String modifiePar;

    @Column(name = "date_suppression")
    private LocalDateTime dateSuppression; // Soft delete

    // ===== RELATIONS CONSERVÉES =====
    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<PatientAssurance> assurances = new ArrayList<>();

    @OneToMany(mappedBy = "patient", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @Builder.Default
    private List<Ordonnance> ordonnances = new ArrayList<>();

    // ===== MÉTHODES UTILITAIRES =====

    /**
     * Vérifie si le patient est actif (non supprimé)
     */
    public boolean isActive() {
        return dateSuppression == null && statut == PatientStatus.ACTIF;
    }

    /**
     * Obtient le numéro de sécurité sociale masqué
     */
    public String getNumeroSecuMasque() {
        if (numeroSecu == null || numeroSecu.length() < 15) {
            return "***************";
        }
        return numeroSecu.substring(0, 1) + " " +
                "**" + " " +
                "**" + " " +
                "***" + " " +
                "***" + " " +
                numeroSecu.substring(13);
    }

    /**
     * Obtient l'adresse complète formatée
     */
    public String getAdresseComplete() {
        StringBuilder sb = new StringBuilder();
        sb.append(adresseLigne1);
        if (adresseLigne2 != null && !adresseLigne2.trim().isEmpty()) {
            sb.append(", ").append(adresseLigne2);
        }
        sb.append(", ").append(codePostal).append(" ").append(ville);
        if (!pays.equals("France")) {
            sb.append(", ").append(pays);
        }
        return sb.toString();
    }

    /**
     * Obtient le nom complet du patient
     */
    public String getNomComplet() {
        return prenom + " " + nom;
    }

    /**
     * Calcule l'âge du patient
     */
    public int getAge() {
        if (dateNaissance == null) {
            return 0;
        }
        return LocalDate.now().getYear() - dateNaissance.getYear();
    }

    /**
     * Ajoute une assurance
     */
    public void addAssurance(PatientAssurance assurance) {
        assurance.setPatient(this);
        this.assurances.add(assurance);
    }

    /**
     * Ajoute une ordonnance
     */
    public void addOrdonnance(Ordonnance ordonnance) {
        ordonnance.setPatient(this);
        this.ordonnances.add(ordonnance);
    }

    /**
     * Vérifie si le patient a donné son consentement pour les notifications
     */
    public boolean hasNotificationConsent() {
        return consentementEmail || consentementSms;
    }

    /**
     * Vérifie si le patient accepte les notifications d'un type donné
     */
    public boolean acceptsNotification(String type) {
        return switch (type.toLowerCase()) {
            case "resultats" -> notificationsResultats != null && notificationsResultats;
            case "rdv" -> notificationsRdv != null && notificationsRdv;
            case "rappels" -> notificationsRappels != null && notificationsRappels;
            default -> false;
        };
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/entity/PatientAssurance.java

```java
package com.lims.patient.entity;

import com.lims.patient.enums.InsuranceType;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité Assurance
 */
@Entity
@Table(name = "patient_assurances", schema = "lims_patient")
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatientAssurance {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", nullable = false)
    private Patient patient;

    @Enumerated(EnumType.STRING)
    @Column(name = "type_assurance", nullable = false)
    private InsuranceType typeAssurance;

    @Column(name = "nom_organisme", nullable = false)
    private String nomOrganisme;

    @Column(name = "numero_adherent", nullable = false, length = 100)
    private String numeroAdherent;

    @Column(name = "date_debut", nullable = false)
    private LocalDate dateDebut;

    @Column(name = "date_fin")
    private LocalDate dateFin;

    @Column(name = "est_active", nullable = false)
    private Boolean estActive = true;

    @Column(name = "tiers_payant_autorise")
    private Boolean tiersPayantAutorise = false;

    @Column(name = "pourcentage_prise_charge", columnDefinition = "DECIMAL(5,2)")
    private BigDecimal pourcentagePriseCharge;

    @Column(name = "reference_document", length = 500)
    private String referenceDocument; // Clé MinIO

    @Column(name = "date_upload_document")
    private LocalDateTime dateUploadDocument;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    /**
     * Vérifie si l'assurance est actuellement valide
     */
    public boolean isCurrentlyValid() {
        LocalDate now = LocalDate.now();
        return estActive &&
                (dateDebut == null || !now.isBefore(dateDebut)) &&
                (dateFin == null || !now.isAfter(dateFin));
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/entity/PatientAuditLog.java

```java
package com.lims.patient.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité pour l'audit trail des patients (conformité RGPD)
 */
@Entity
@Table(name = "audit_logs", schema = "lims_patient")
@Builder
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class PatientAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "patient_id")
    private UUID patientId;

    @Column(name = "action", nullable = false, length = 100)
    private String action;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "table_concernee", length = 100)
    private String tableConcernee;

    @Column(name = "id_enregistrement", length = 100)
    private String idEnregistrement;

    // Qui a effectué l'action
    @Column(name = "effectue_par", nullable = false, length = 100)
    private String performedBy;

    @Column(name = "type_utilisateur", nullable = false, length = 20)
    private String performedByType;

    @Column(name = "realm_utilisateur", length = 50)
    private String realmUtilisateur;

    // Contexte technique
    @Column(name = "adresse_ip", columnDefinition = "INET")
    @Pattern(regexp = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
            message = "Format d'adresse IP invalide")
    private String clientIp;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "session_id", length = 100)
    private String sessionId;

    // Données modifiées (pour audit détaillé)
    @Column(name = "anciennes_valeurs", columnDefinition = "JSONB")
    private String anciennesValeurs;

    @Column(name = "nouvelles_valeurs", columnDefinition = "JSONB")
    private String nouvellesValeurs;

    // Résultat de l'action
    @Column(name = "resultat", nullable = false, length = 20)
    private String result;

    @Column(name = "message_erreur", columnDefinition = "TEXT")
    private String messageErreur;

    @CreatedDate
    @Column(name = "date_action", nullable = false)
    private LocalDateTime dateAction;

    @Column(name = "correlation_id")
    private UUID correlationId;
}
```

# lims-patient-service/src/main/java/com/lims/patient/enums/AddressType.java

```java
package com.lims.patient.enums;

public enum AddressType {
    DOMICILE("Domicile"),
    TRAVAIL("Travail"),
    FACTURATION("Facturation"),
    CORRESPONDANCE("Correspondance");

    private final String label;

    AddressType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/ContactType.java

```java
package com.lims.patient.enums;


public enum ContactType {
    MOBILE("Mobile"),
    FIXE("Fixe"),
    PROFESSIONNEL("Professionnel"),
    URGENCE("Urgence");

    private final String label;

    ContactType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/DeliveryMethod.java

```java
package com.lims.patient.enums;

public enum DeliveryMethod {
    EMAIL("Email"),
    SMS("SMS"),
    COURRIER("Courrier"),
    RETRAIT_PLACE("Retrait sur place"),
    TELEPHONE("Téléphone");

    private final String label;

    DeliveryMethod(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/GenderType.java

```java
package com.lims.patient.enums;

public enum GenderType {
    M("Masculin"),
    F("Féminin"),
    NON_BINAIRE("Non binaire"),
    NON_PRECISE("Non précisé");

    private final String label;

    GenderType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/InsuranceType.java

```java
package com.lims.patient.enums;

public enum InsuranceType {
    PRIMAIRE("Assurance primaire (Sécurité Sociale)"),
    COMPLEMENTAIRE("Assurance complémentaire (Mutuelle)"),
    SPECIAL("Régime spécial (CMU-C, ACS, AME)");

    private final String label;

    InsuranceType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/NotificationPreference.java

```java
package com.lims.patient.enums;

public enum NotificationPreference {
    TOUS("Toutes les notifications"),
    URGENCE_UNIQUEMENT("Urgences uniquement"),
    AUCUNE("Aucune notification");

    private final String label;

    NotificationPreference(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/PatientStatus.java

```java
package com.lims.patient.enums;

public enum PatientStatus {
    ACTIF("Actif"),
    INACTIF("Inactif"),
    SUSPENDU("Suspendu"),
    DECEDE("Décédé");

    private final String label;

    PatientStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/enums/PrescriptionStatus.java

```java
package com.lims.patient.enums;

public enum PrescriptionStatus {
    EN_ATTENTE("En attente"),
    VALIDEE("Validée"),
    TRAITEE("Traitée"),
    EXPIREE("Expirée"),
    ANNULEE("Annulée");

    private final String label;

    PrescriptionStatus(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/exception/ConsentValidationException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand la validation des consentements RGPD échoue
 */
public class ConsentValidationException extends RuntimeException {

    public ConsentValidationException(String message) {
        super(message);
    }

    public ConsentValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConsentValidationException(String consentType, String reason) {
        super(String.format("Validation du consentement '%s' échoué: %s", consentType, reason));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/DuplicatePatientException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand un patient en doublon est détecté
 */
public class DuplicatePatientException extends RuntimeException {

    public DuplicatePatientException(String message) {
        super(message);
    }

    public DuplicatePatientException(String message, Throwable cause) {
        super(message, cause);
    }

    public DuplicatePatientException(String message, String field, String value) {
        super(String.format("%s - Champ: %s, Valeur: %s", message, field, value));
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/exception/InvalidPatientDataException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand les données du patient sont invalides
 */
public class InvalidPatientDataException extends RuntimeException {

    public InvalidPatientDataException(String message) {
        super(message);
    }

    public InvalidPatientDataException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidPatientDataException(String field, String message) {
        super(String.format("Champ '%s': %s", field, message));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/InvalidSearchCriteriaException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand les données de recherche sont invalides
 */
public class InvalidSearchCriteriaException extends RuntimeException {

    public InvalidSearchCriteriaException(String message) {
        super(message);
    }

    public InvalidSearchCriteriaException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSearchCriteriaException(String criteria, String reason) {
        super(String.format("Critère de recherche '%s' invalide: %s", criteria, reason));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientAccessDeniedException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand l'accès à un patient est refusé
 */
public class PatientAccessDeniedException extends RuntimeException {

    public PatientAccessDeniedException(String message) {
        super(message);
    }

    public PatientAccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientAccessDeniedException(String patientId, String userId, String reason) {
        super(String.format("Accès refusé au patient %s pour l'utilisateur %s: %s", patientId, userId, reason));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientBusinessRuleException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand une contrainte métier est violée
 */
public class PatientBusinessRuleException extends RuntimeException {

    public PatientBusinessRuleException(String message) {
        super(message);
    }

    public PatientBusinessRuleException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientBusinessRuleException(String rule, String violation) {
        super(String.format("Règle métier '%s' violée: %s", rule, violation));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientExceptionHandler.java

```java
package com.lims.patient.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Gestionnaire global des exceptions pour le module Patient
 */
@RestControllerAdvice
@Slf4j
public class PatientExceptionHandler {

    @ExceptionHandler(PatientNotFoundException.class)
    public ResponseEntity<ErrorResponse> handlePatientNotFound(PatientNotFoundException ex, WebRequest request) {
        log.error("Patient non trouvé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Patient Not Found")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    @ExceptionHandler(DuplicatePatientException.class)
    public ResponseEntity<ErrorResponse> handleDuplicatePatient(DuplicatePatientException ex, WebRequest request) {
        log.error("Patient en doublon: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.CONFLICT.value())
                .error("Duplicate Patient")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    @ExceptionHandler(InvalidPatientDataException.class)
    public ResponseEntity<ErrorResponse> handleInvalidPatientData(InvalidPatientDataException ex, WebRequest request) {
        log.error("Données patient invalides: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Invalid Patient Data")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(PatientOperationNotAllowedException.class)
    public ResponseEntity<ErrorResponse> handleOperationNotAllowed(PatientOperationNotAllowedException ex, WebRequest request) {
        log.error("Opération non autorisée: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Operation Not Allowed")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(InvalidSearchCriteriaException.class)
    public ResponseEntity<ErrorResponse> handleInvalidSearchCriteria(InvalidSearchCriteriaException ex, WebRequest request) {
        log.error("Critères de recherche invalides: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Invalid Search Criteria")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(ConsentValidationException.class)
    public ResponseEntity<ErrorResponse> handleConsentValidation(ConsentValidationException ex, WebRequest request) {
        log.error("Validation du consentement échoué: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Consent Validation Failed")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(PatientAccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(PatientAccessDeniedException ex, WebRequest request) {
        log.error("Accès refusé: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Access Denied")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(PatientBusinessRuleException.class)
    public ResponseEntity<ErrorResponse> handleBusinessRule(PatientBusinessRuleException ex, WebRequest request) {
        log.error("Règle métier violée: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNPROCESSABLE_ENTITY.value())
                .error("Business Rule Violation")
                .message(ex.getMessage())
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, WebRequest request) {
        log.error("Erreur inattendue: {}", ex.getMessage(), ex);

        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Internal Server Error")
                .message("Une erreur inattendue s'est produite")
                .path(request.getDescription(false))
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    /**
     * Classe pour les réponses d'erreur
     */
    public static class ErrorResponse {
        private LocalDateTime timestamp;
        private int status;
        private String error;
        private String message;
        private String path;
        private Map<String, Object> details;

        // Constructeurs
        public ErrorResponse() {
            this.details = new HashMap<>();
        }

        public ErrorResponse(LocalDateTime timestamp, int status, String error, String message, String path) {
            this.timestamp = timestamp;
            this.status = status;
            this.error = error;
            this.message = message;
            this.path = path;
            this.details = new HashMap<>();
        }

        // Builder pattern
        public static ErrorResponseBuilder builder() {
            return new ErrorResponseBuilder();
        }

        public static class ErrorResponseBuilder {
            private LocalDateTime timestamp;
            private int status;
            private String error;
            private String message;
            private String path;
            private Map<String, Object> details = new HashMap<>();

            public ErrorResponseBuilder timestamp(LocalDateTime timestamp) {
                this.timestamp = timestamp;
                return this;
            }

            public ErrorResponseBuilder status(int status) {
                this.status = status;
                return this;
            }

            public ErrorResponseBuilder error(String error) {
                this.error = error;
                return this;
            }

            public ErrorResponseBuilder message(String message) {
                this.message = message;
                return this;
            }

            public ErrorResponseBuilder path(String path) {
                this.path = path;
                return this;
            }

            public ErrorResponseBuilder detail(String key, Object value) {
                this.details.put(key, value);
                return this;
            }

            public ErrorResponse build() {
                ErrorResponse response = new ErrorResponse();
                response.timestamp = this.timestamp;
                response.status = this.status;
                response.error = this.error;
                response.message = this.message;
                response.path = this.path;
                response.details = this.details;
                return response;
            }
        }

        // Getters et setters
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

        public int getStatus() { return status; }
        public void setStatus(int status) { this.status = status; }

        public String getError() { return error; }
        public void setError(String error) { this.error = error; }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }

        public Map<String, Object> getDetails() { return details; }
        public void setDetails(Map<String, Object> details) { this.details = details; }
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientMappingException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand une erreur de mapping se produit
 */
public class PatientMappingException extends RuntimeException {

    public PatientMappingException(String message) {
        super(message);
    }

    public PatientMappingException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientMappingException(String sourceType, String targetType, String reason) {
        super(String.format("Erreur de mapping de %s vers %s: %s", sourceType, targetType, reason));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientNotFoundException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand un patient n'est pas trouvé
 */
public class PatientNotFoundException extends RuntimeException {

    public PatientNotFoundException(String message) {
        super(message);
    }

    public PatientNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientNotFoundException(String message, String patientId) {
        super(String.format("%s - Patient ID: %s", message, patientId));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/exception/PatientOperationNotAllowedException.java

```java
package com.lims.patient.exception;

/**
 * Exception lancée quand une opération sur un patient n'est pas autorisée
 */
public class PatientOperationNotAllowedException extends RuntimeException {

    public PatientOperationNotAllowedException(String message) {
        super(message);
    }

    public PatientOperationNotAllowedException(String message, Throwable cause) {
        super(message, cause);
    }

    public PatientOperationNotAllowedException(String operation, String reason) {
        super(String.format("Opération '%s' non autorisée: %s", operation, reason));
    }
}

```

# lims-patient-service/src/main/java/com/lims/patient/mapper/PatientAuditMapper.java

```java
package com.lims.patient.mapper;

import com.lims.patient.dto.response.AuditLogResponse;
import com.lims.patient.entity.PatientAuditLog;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

import java.util.List;

/**
 * Mapper pour les logs d'audit
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE
)
public interface PatientAuditMapper {

    @Mapping(target = "patientId", source = "patientId", qualifiedByName = "uuidToString")
    @Mapping(target = "correlationId", source = "correlationId", qualifiedByName = "uuidToString")
    AuditLogResponse toAuditLogResponse(PatientAuditLog auditLog);

    List<AuditLogResponse> toAuditLogResponseList(List<PatientAuditLog> auditLogs);

    @org.mapstruct.Named("uuidToString")
    default String uuidToString(java.util.UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/mapper/PatientConfigMapper.java

```java
package com.lims.patient.mapper;

import com.lims.patient.dto.config.PatientBusinessRules;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

/**
 * Mapper pour les configurations
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE
)
public interface PatientConfigMapper {

    /**
     * Convertit les règles métier en DTO de configuration
     */
    PatientBusinessRules toPatientBusinessRules(
            Integer maxContactsParType,
            Integer maxAdressesParType,
            Integer maxAssurancesParPatient,
            Boolean validationEmailObligatoire,
            Boolean validationTelephoneObligatoire,
            Integer dureeConservationAuditJours,
            Boolean softDeleteUniquement
    );
}
```

# lims-patient-service/src/main/java/com/lims/patient/mapper/PatientMapper.java

```java
package com.lims.patient.mapper;

import com.lims.patient.dto.response.*;
import com.lims.patient.entity.*;
import com.lims.patient.enums.PrescriptionStatus;
import org.mapstruct.*;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.UUID;

/**
 * Mapper principal pour convertir les entités Patient en DTOs - Version centralisée
 * Utilise MapStruct pour la génération automatique du code
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface PatientMapper {

    // ============================================
    // PATIENT PRINCIPAL
    // ============================================

    /**
     * Convertit une entité Patient en PatientResponse complet
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "personalInfo", source = ".", qualifiedByName = "toPersonalInfoResponse")
    @Mapping(target = "contactInfo", source = ".", qualifiedByName = "toContactInfoResponse")
    @Mapping(target = "insurances", source = "assurances")
    @Mapping(target = "consent", source = ".", qualifiedByName = "toConsentResponse")
    @Mapping(target = "metadata", source = ".", qualifiedByName = "toMetadataResponse")
    PatientResponse toPatientResponse(Patient patient);

    /**
     * Convertit une entité Patient en PatientSummaryResponse pour les listes
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "nomComplet", source = ".", qualifiedByName = "buildFullName")
    @Mapping(target = "email", source = "email")
    @Mapping(target = "telephone", source = "telephone")
    @Mapping(target = "dateNaissance", source = "dateNaissance")
    @Mapping(target = "age", source = ".", qualifiedByName = "calculateAge")
    @Mapping(target = "sexe", source = "sexe")
    @Mapping(target = "ville", source = "ville")
    @Mapping(target = "statut", source = "statut")
    @Mapping(target = "dateCreation", source = "dateCreation")
    PatientSummaryResponse toPatientSummaryResponse(Patient patient);

    // ============================================
    // MAPPERS POUR SOUS-OBJETS
    // ============================================

    /**
     * Mappe les informations personnelles
     */
    @Named("toPersonalInfoResponse")
    default PersonalInfoResponse toPersonalInfoResponse(Patient patient) {
        if (patient == null) return null;

        return PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(maskNIR(patient))
                .age(calculateAge(patient))
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();
    }

    /**
     * Mappe les informations de contact centralisées
     */
    @Named("toContactInfoResponse")
    default ContactInfoResponse toContactInfoResponse(Patient patient) {
        if (patient == null) return null;

        return ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .adresseComplete(buildAdresseComplete(patient))
                .adresseLigne1(patient.getAdresseLigne1())
                .adresseLigne2(patient.getAdresseLigne2())
                .codePostal(patient.getCodePostal())
                .ville(patient.getVille())
                .departement(patient.getDepartement())
                .region(patient.getRegion())
                .pays(patient.getPays())
                .latitude(patient.getLatitude())
                .longitude(patient.getLongitude())
                .methodeLivraisonPreferee(patient.getMethodeLivraisonPreferee())
                .preferenceNotification(patient.getPreferenceNotification())
                .languePreferee(patient.getLanguePreferee())
                .notificationsResultats(patient.getNotificationsResultats())
                .notificationsRdv(patient.getNotificationsRdv())
                .notificationsRappels(patient.getNotificationsRappels())
                .build();
    }

    /**
     * Mappe les consentements
     */
    @Named("toConsentResponse")
    default ConsentResponse toConsentResponse(Patient patient) {
        if (patient == null) return null;

        return ConsentResponse.builder()
                .consentementCreationCompte(patient.getConsentementCreationCompte())
                .consentementSms(patient.getConsentementSms())
                .consentementEmail(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();
    }

    /**
     * Mappe les métadonnées
     */
    @Named("toMetadataResponse")
    default MetadataResponse toMetadataResponse(Patient patient) {
        if (patient == null) return null;

        return MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .actif(patient.isActive())
                .build();
    }

    // ============================================
    // MAPPERS POUR ENTITÉS LIÉES (CONSERVÉES)
    // ============================================

    /**
     * Mappe les assurances
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "estActive", source = "estActive")
    InsuranceResponse toInsuranceResponse(PatientAssurance assurance);

    List<InsuranceResponse> toInsuranceResponseList(List<PatientAssurance> assurances);

    /**
     * Mappe les ordonnances en résumé
     */
    @Named("toPrescriptionSummaryList")
    default List<PrescriptionSummaryResponse> toPrescriptionSummaryList(List<Ordonnance> ordonnances) {
        if (ordonnances == null) return List.of();

        return ordonnances.stream()
                .filter(o -> o.getDateSuppression() == null) // Exclut les supprimées
                .map(this::toPrescriptionSummaryResponse)
                .toList();
    }

    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "nombreAnalyses", source = "analyses", qualifiedByName = "countAnalyses")
    PrescriptionSummaryResponse toPrescriptionSummaryResponse(Ordonnance ordonnance);

    // ============================================
    // MÉTHODES UTILITAIRES ADAPTÉES
    // ============================================

    /**
     * Convertit UUID en String
     */
    @Named("uuidToString")
    default String uuidToString(UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }

    /**
     * Construit l'adresse complète
     */
    default String buildAdresseComplete(Patient patient) {
        if (patient == null) return null;

        StringBuilder sb = new StringBuilder();

        if (patient.getAdresseLigne1() != null) {
            sb.append(patient.getAdresseLigne1());
        }

        if (patient.getAdresseLigne2() != null && !patient.getAdresseLigne2().trim().isEmpty()) {
            sb.append(", ").append(patient.getAdresseLigne2());
        }

        if (patient.getCodePostal() != null && patient.getVille() != null) {
            sb.append(", ").append(patient.getCodePostal()).append(" ").append(patient.getVille());
        }

        if (patient.getPays() != null && !patient.getPays().equals("France")) {
            sb.append(", ").append(patient.getPays());
        }

        return sb.toString();
    }

    /**
     * Vérifie si le patient a une assurance active
     */
    @Named("hasActiveInsurance")
    default Boolean hasActiveInsurance(Patient patient) {
        if (patient == null || patient.getAssurances() == null) return false;

        return patient.getAssurances().stream()
                .anyMatch(assurance -> assurance.getEstActive() != null && assurance.getEstActive() &&
                        (assurance.getDateFin() == null || assurance.getDateFin().isAfter(LocalDate.now())));
    }

    /**
     * Vérifie si le patient a une ordonnance en cours
     */
    @Named("hasActivePrescription")
    default Boolean hasActivePrescription(Patient patient) {
        if (patient == null || patient.getOrdonnances() == null) return false;

        return patient.getOrdonnances().stream()
                .anyMatch(o -> o.getDateSuppression() == null &&
                        (o.getStatut() == PrescriptionStatus.EN_ATTENTE ||
                                o.getStatut() == PrescriptionStatus.VALIDEE));
    }

    /**
     * Compte le nombre d'analyses dans une ordonnance
     */
    @Named("countAnalyses")
    default Integer countAnalyses(List<OrdonnanceAnalyse> analyses) {
        return analyses != null ? analyses.size() : 0;
    }

    /**
     * Construit le nom complet
     */
    @Named("buildFullName")
    default String buildFullName(Patient patient) {
        if (patient == null) return null;

        StringBuilder sb = new StringBuilder();

        if (patient.getPrenom() != null) {
            sb.append(patient.getPrenom());
        }

        if (patient.getNom() != null) {
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(patient.getNom());
        }

        return sb.toString();
    }

    /**
     * Vérifie si le patient est mineur
     */
    @Named("isMinor")
    default Boolean isMinor(Patient patient) {
        if (patient == null || patient.getDateNaissance() == null) return false;
        return patient.getDateNaissance().isAfter(LocalDate.now().minusYears(18));
    }

    /**
     * Calcule l'âge du patient
     */
    @Named("calculateAge")
    default Integer calculateAge(Patient patient) {
        if (patient == null || patient.getDateNaissance() == null) return 0;
        return Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
    }

    /**
     * Masque le numéro de sécurité sociale
     */
    @Named("maskNIR")
    default String maskNIR(Patient patient) {
        if (patient == null || patient.getNumeroSecu() == null) {
            return "***************";
        }

        String nir = patient.getNumeroSecu();
        if (nir.length() >= 8) {
            return nir.substring(0, 4) + "*******" + nir.substring(nir.length() - 4);
        }
        return "***************";
    }

    /**
     * Formatage du téléphone pour l'affichage
     */
    default String formatTelephone(String telephone) {
        if (telephone == null || telephone.isEmpty()) return null;

        // Supprime les espaces et caractères spéciaux
        String cleaned = telephone.replaceAll("[^0-9+]", "");

        // Format français : +33 1 23 45 67 89
        if (cleaned.startsWith("+33") && cleaned.length() == 12) {
            return cleaned.substring(0, 3) + " " +
                    cleaned.substring(3, 4) + " " +
                    cleaned.substring(4, 6) + " " +
                    cleaned.substring(6, 8) + " " +
                    cleaned.substring(8, 10) + " " +
                    cleaned.substring(10, 12);
        }

        return telephone; // Retourne tel quel si pas de format reconnu
    }

    /**
     * Validation de l'email
     */
    default Boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) return false;
        return email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    /**
     * Validation du téléphone
     */
    default Boolean isValidTelephone(String telephone) {
        if (telephone == null || telephone.isEmpty()) return false;
        return telephone.matches("^\\+[1-9][0-9]{8,14}$");
    }

    /**
     * Obtient le statut de validation du patient
     */
    default String getValidationStatus(Patient patient) {
        if (patient == null) return "INVALID";

        boolean hasValidEmail = isValidEmail(patient.getEmail());
        boolean hasValidTelephone = isValidTelephone(patient.getTelephone());
        boolean hasValidAddress = patient.getAdresseLigne1() != null &&
                patient.getCodePostal() != null &&
                patient.getVille() != null;

        if (hasValidEmail && hasValidTelephone && hasValidAddress) {
            return "COMPLETE";
        } else if (hasValidEmail || hasValidTelephone) {
            return "PARTIAL";
        } else {
            return "INCOMPLETE";
        }
    }

    /**
     * Obtient une représentation courte du patient pour les logs
     */
    default String toLogString(Patient patient) {
        if (patient == null) return "Patient[null]";

        return String.format("Patient[id=%s, nom=%s, prenom=%s, email=%s]",
                patient.getId(),
                patient.getNom(),
                patient.getPrenom(),
                patient.getEmail());
    }

    /**
     * Vérifie si le patient a des notifications activées
     */
    default Boolean hasNotificationsEnabled(Patient patient) {
        if (patient == null) return false;

        return (patient.getNotificationsResultats() != null && patient.getNotificationsResultats()) ||
                (patient.getNotificationsRdv() != null && patient.getNotificationsRdv()) ||
                (patient.getNotificationsRappels() != null && patient.getNotificationsRappels());
    }

    /**
     * Obtient les types de notifications activées
     */
    default List<String> getEnabledNotificationTypes(Patient patient) {
        if (patient == null) return List.of();

        List<String> types = new java.util.ArrayList<>();

        if (patient.getNotificationsResultats() != null && patient.getNotificationsResultats()) {
            types.add("RESULTATS");
        }
        if (patient.getNotificationsRdv() != null && patient.getNotificationsRdv()) {
            types.add("RDV");
        }
        if (patient.getNotificationsRappels() != null && patient.getNotificationsRappels()) {
            types.add("RAPPELS");
        }

        return types;
    }

    /**
     * Obtient une description textuelle du statut du patient
     */
    default String getStatusDescription(Patient patient) {
        if (patient == null || patient.getStatut() == null) return "Statut inconnu";

        return switch (patient.getStatut()) {
            case ACTIF -> "Patient actif";
            case INACTIF -> "Patient inactif";
            case SUSPENDU -> "Patient suspendu";
            case DECEDE -> "Patient décédé";
            default -> "Statut inconnu";
        };
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/PatientServiceApplication.java

```java
package com.lims.patient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Application principale du service Patient LIMS
 *
 * Fonctionnalités :
 * - Gestion complète des patients (CRUD)
 * - Recherche avancée multi-critères
 * - Audit trail RGPD
 * - Sécurité avec Keycloak (realms staff et patient)
 * - Validation métier française (NIR, etc.)
 * - Cache Redis
 * - API REST documentée (OpenAPI)
 *
 * Port: 8092
 * Realm Keycloak: lims-patient (patients) + lims-staff (personnel)
 * Base de données: PostgreSQL schema lims_patient
 */
@SpringBootApplication
@EnableCaching
@EnableAsync
@EnableTransactionManagement
@EnableConfigurationProperties
public class PatientServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PatientServiceApplication.class, args);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/repository/OrdonnanceAnalyseRepository.java

```java
package com.lims.patient.repository;

import com.lims.patient.entity.OrdonnanceAnalyse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Repository pour les analyses d'ordonnance
 */
@Repository
public interface OrdonnanceAnalyseRepository extends JpaRepository<OrdonnanceAnalyse, UUID> {

    /**
     * Trouve toutes les analyses d'une ordonnance
     */
    List<OrdonnanceAnalyse> findByOrdonnanceIdOrderByEstUrgentDescDateCreationAsc(UUID ordonnanceId);

    /**
     * Compte les analyses par code
     */
    @Query("SELECT oa.codeAnalyse, COUNT(oa) FROM OrdonnanceAnalyse oa " +
            "WHERE oa.ordonnance.dateSuppression IS NULL " +
            "GROUP BY oa.codeAnalyse ORDER BY COUNT(oa) DESC")
    List<Object[]> countByCodeAnalyse();
}

```

# lims-patient-service/src/main/java/com/lims/patient/repository/OrdonnanceRepository.java

```java
package com.lims.patient.repository;

import com.lims.patient.entity.Ordonnance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

/**
 * Repository pour les ordonnances
 */
@Repository
public interface OrdonnanceRepository extends JpaRepository<Ordonnance, UUID> {

    /**
     * Trouve toutes les ordonnances d'un patient
     */
    List<Ordonnance> findByPatientIdAndDateSuppressionIsNullOrderByDatePrescriptionDesc(UUID patientId);

    /**
     * Trouve les ordonnances actives d'un patient
     */
    @Query("SELECT o FROM Ordonnance o WHERE " +
            "o.patient.id = :patientId AND " +
            "o.statut IN ('EN_ATTENTE', 'VALIDEE') AND " +
            "o.dateSuppression IS NULL")
    List<Ordonnance> findActiveByPatientId(@Param("patientId") UUID patientId);

    /**
     * Compte les patients avec ordonnance active
     */
    @Query("SELECT COUNT(DISTINCT o.patient.id) FROM Ordonnance o WHERE " +
            "o.statut IN ('EN_ATTENTE', 'VALIDEE') AND " +
            "o.dateSuppression IS NULL AND " +
            "o.patient.dateSuppression IS NULL")
    long countPatientsWithActivePrescription();

    /**
     * Trouve les ordonnances renouvelables qui expirent bientôt
     */
    @Query("SELECT o FROM Ordonnance o WHERE " +
            "o.estRenouvelable = true AND " +
            "o.renouvelableJusqu BETWEEN CURRENT_DATE AND :dateLimit AND " +
            "o.dateSuppression IS NULL")
    List<Ordonnance> findRenewableExpiringBefore(@Param("dateLimit") LocalDate dateLimit);
}

```

# lims-patient-service/src/main/java/com/lims/patient/repository/PatientAssuranceRepository.java

```java
package com.lims.patient.repository;

import com.lims.patient.entity.PatientAssurance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les assurances
 */
@Repository
public interface PatientAssuranceRepository extends JpaRepository<PatientAssurance, UUID> {

    /**
     * Trouve toutes les assurances d'un patient
     */
    List<PatientAssurance> findByPatientIdOrderByDateDebutDescTypeAssuranceAsc(UUID patientId);

    /**
     * Trouve les assurances actives d'un patient
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE " +
            "pa.patient.id = :patientId AND " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE) AND " +
            "pa.patient.dateSuppression IS NULL")
    List<PatientAssurance> findActiveByPatientId(@Param("patientId") UUID patientId);

    /**
     * Trouve l'assurance primaire active d'un patient
     */
    @Query("SELECT pa FROM PatientAssurance pa WHERE " +
            "pa.patient.id = :patientId AND " +
            "pa.typeAssurance = 'PRIMAIRE' AND " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE)")
    Optional<PatientAssurance> findActivePrimaryInsurance(@Param("patientId") UUID patientId);

    /**
     * Compte les patients avec assurance active
     */
    @Query("SELECT COUNT(DISTINCT pa.patient.id) FROM PatientAssurance pa WHERE " +
            "pa.estActive = true AND " +
            "(pa.dateFin IS NULL OR pa.dateFin >= CURRENT_DATE) AND " +
            "pa.patient.dateSuppression IS NULL")
    long countPatientsWithActiveInsurance();
}

```

# lims-patient-service/src/main/java/com/lims/patient/repository/PatientAuditLogRepository.java

```java
package com.lims.patient.repository;

import com.lims.patient.entity.PatientAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository pour l'audit des patients
 */
@Repository
public interface PatientAuditLogRepository extends JpaRepository<PatientAuditLog, Long> {

    /**
     * Trouve les logs d'audit d'un patient
     */
    List<PatientAuditLog> findByPatientIdOrderByDateActionDesc(UUID patientId);

    /**
     * Trouve les logs d'audit par utilisateur
     */
    List<PatientAuditLog> findByPerformedByOrderByDateActionDesc(String performedBy);

    /**
     * Trouve les logs d'audit par action
     */
    List<PatientAuditLog> findByActionOrderByDateActionDesc(String action);

    /**
     * Trouve les logs d'audit récents
     */
    @Query("SELECT pal FROM PatientAuditLog pal WHERE " +
            "pal.dateAction >= :dateDebut " +
            "ORDER BY pal.dateAction DESC")
    List<PatientAuditLog> findRecentLogs(@Param("dateDebut") LocalDateTime dateDebut);

    /**
     * Supprime les logs d'audit anciens (RGPD - conservation limitée)
     */
    @Query("DELETE FROM PatientAuditLog pal WHERE pal.dateAction < :dateLimit")
    void deleteOldLogs(@Param("dateLimit") LocalDateTime dateLimit);
}

```

# lims-patient-service/src/main/java/com/lims/patient/repository/PatientRepository.java

```java
package com.lims.patient.repository;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour les patients - Version avec Specifications
 */
@Repository
public interface PatientRepository extends JpaRepository<Patient, UUID>, JpaSpecificationExecutor<Patient> {

    // ===== RECHERCHES DE BASE SIMPLES =====

    /**
     * Trouve un patient par ID (non supprimé)
     */
    Optional<Patient> findByIdAndDateSuppressionIsNull(UUID id);

    /**
     * Trouve un patient par numéro de sécurité sociale
     */
    Optional<Patient> findByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Trouve un patient par email (égalité exacte)
     */
    Optional<Patient> findByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Trouve un patient par téléphone
     */
    Optional<Patient> findByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===== VÉRIFICATIONS D'EXISTENCE =====

    /**
     * Vérifie si un patient existe avec ce numéro de sécurité sociale
     */
    boolean existsByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Vérifie si un patient existe avec cet email (insensible à la casse)
     */
    boolean existsByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Vérifie si un patient existe avec ce téléphone
     */
    boolean existsByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===== RECHERCHES PAR STATUT =====

    /**
     * Trouve tous les patients par statut
     */
    Page<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut, Pageable pageable);

    /**
     * Trouve tous les patients actifs
     */
    List<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut);

    // ===== RECHERCHES SPÉCIALISÉES (gardées pour compatibilité) =====

    /**
     * Recherche par nom et prénom (utilise les methods queries Spring Data)
     */
    List<Patient> findByNomContainingIgnoreCaseAndDateSuppressionIsNull(String nom);

    /**
     * Recherche par ville
     */
    List<Patient> findByVilleContainingIgnoreCaseAndDateSuppressionIsNull(String ville);

    /**
     * Recherche par date de naissance
     */
    List<Patient> findByDateNaissanceAndDateSuppressionIsNull(LocalDate dateNaissance);

    /**
     * Recherche par sexe
     */
    List<Patient> findBySexeAndDateSuppressionIsNull(GenderType sexe);

    /**
     * Recherche par région
     */
    List<Patient> findByRegionAndDateSuppressionIsNull(String region);

    /**
     * Recherche par département
     */
    List<Patient> findByDepartementAndDateSuppressionIsNull(String departement);

    // ===== RECHERCHES AVEC REQUÊTES PERSONNALISÉES (si nécessaire) =====

    /**
     * Recherche par proximité géographique
     */
    @Query(value = "SELECT * FROM lims_patient.patients p WHERE " +
            "p.date_suppression IS NULL AND " +
            "p.latitude IS NOT NULL AND p.longitude IS NOT NULL AND " +
            "ST_DWithin(ST_MakePoint(p.longitude, p.latitude)::geography, " +
            "ST_MakePoint(:longitude, :latitude)::geography, :rayonMetres)",
            nativeQuery = true)
    List<Patient> findByProximity(@Param("latitude") Double latitude,
                                  @Param("longitude") Double longitude,
                                  @Param("rayonMetres") Double rayonMetres);

    // ===== RECHERCHES DE PATIENTS AVEC CONDITIONS SPÉCIALES =====

    /**
     * Trouve les patients avec notifications activées
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = 'ACTIF' AND " +
            "(p.notificationsResultats = true OR p.notificationsRdv = true OR p.notificationsRappels = true)")
    List<Patient> findPatientsWithNotificationsEnabled();

    /**
     * Trouve les patients avec allergies
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.allergiesConnues IS NOT NULL AND " +
            "p.allergiesConnues != '' AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithAllergies();

    /**
     * Trouve les patients avec antécédents médicaux
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.antecedentsMedicaux IS NOT NULL AND " +
            "p.antecedentsMedicaux != '' AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findPatientsWithMedicalHistory();

    // ===== STATISTIQUES =====

    /**
     * Compte le nombre de patients par statut
     */
    @Query("SELECT p.statut, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.statut")
    List<Object[]> countPatientsByStatus();

    /**
     * Compte le nombre de patients par sexe
     */
    @Query("SELECT p.sexe, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.sexe")
    List<Object[]> countPatientsByGender();

    /**
     * Compte le nombre de patients par ville
     */
    @Query("SELECT p.ville, COUNT(p) FROM Patient p WHERE " +
            "p.dateSuppression IS NULL GROUP BY p.ville ORDER BY COUNT(p) DESC")
    List<Object[]> countPatientsByCity();

    /**
     * Compte le nombre total de patients actifs
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL AND p.statut = 'ACTIF'")
    long countActivePatients();

    // ===== REQUÊTES DE MAINTENANCE =====

    /**
     * Trouve les patients récemment modifiés
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateModification > :dateLimit AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findRecentlyModifiedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    // NOTE: Plus besoin de findByMultipleCriteria complexe !
    // La recherche multicritères se fait maintenant avec les Specifications
}
```

# lims-patient-service/src/main/java/com/lims/patient/security/PatientSecurityContext.java

```java
package com.lims.patient.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.UUID;

/**
 * Contexte de sécurité pour le service Patient.
 * Fournit des méthodes utilitaires pour accéder aux informations de l'utilisateur connecté.
 */
@Slf4j
@Component
public class PatientSecurityContext {

    /**
     * Récupère l'authentification courante
     */
    private Authentication getCurrentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * Récupère le JWT de l'utilisateur connecté
     */
    private Jwt getCurrentJwt() {
        Authentication auth = getCurrentAuthentication();
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            return jwtAuth.getToken();
        }
        return null;
    }

    /**
     * Récupère l'ID de l'utilisateur connecté
     */
    public String getCurrentUserId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getSubject() : null;
    }

    /**
     * Récupère l'email de l'utilisateur connecté
     */
    public String getCurrentUserEmail() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("email") : null;
    }

    /**
     * Récupère le type d'utilisateur connecté
     */
    public String getCurrentUserType() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("user_type") : null;
    }

    /**
     * Récupère le rôle de l'utilisateur connecté
     */
    public String getCurrentUserRole() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("role") : null;
    }

    /**
     * Récupère le realm de l'utilisateur connecté
     */
    public String getCurrentUserRealm() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("realm") : null;
    }

    /**
     * Récupère l'ID du laboratoire de l'utilisateur connecté (pour le staff)
     */
    public String getCurrentUserLaboratoryId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("laboratory_id") : null;
    }

    /**
     * Récupère l'ID patient de l'utilisateur connecté (pour les patients)
     */
    public String getCurrentPatientId() {
        Jwt jwt = getCurrentJwt();
        return jwt != null ? jwt.getClaimAsString("patient_id") : null;
    }

    /**
     * Vérifie si l'utilisateur connecté est un admin
     */
    public boolean isCurrentUserAdmin() {
        String userType = getCurrentUserType();
        return "ADMIN".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur connecté est un patient
     */
    public boolean isCurrentUserPatient() {
        String userType = getCurrentUserType();
        return "PATIENT".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur connecté est un membre du staff
     */
    public boolean isCurrentUserStaff() {
        String userType = getCurrentUserType();
        return "STAFF".equals(userType);
    }

    /**
     * Vérifie si l'utilisateur a une autorité spécifique
     */
    private boolean hasAuthority(String authority) {
        Authentication auth = getCurrentAuthentication();
        if (auth != null) {
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            return authorities.stream()
                    .anyMatch(a -> a.getAuthority().equals(authority));
        }
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut accéder aux données d'un patient spécifique
     */
    public boolean canAccessPatient(UUID patientId) {
        log.debug("Checking access to patient {} for user {}", patientId, getCurrentUserId());

        // Les admins ont accès à tous les patients
        if (isCurrentUserAdmin()) {
            log.debug("Admin access granted to patient {}", patientId);
            return true;
        }

        // Les patients peuvent accéder à leurs propres données
        if (isCurrentUserPatient()) {
            String currentPatientId = getCurrentPatientId();
            boolean hasAccess = patientId.toString().equals(currentPatientId);
            log.debug("Patient access to patient {}: {}", patientId, hasAccess);
            return hasAccess;
        }

        // Le staff peut accéder aux patients de leur laboratoire
        if (isCurrentUserStaff()) {
            // Pour l'instant, on permet l'accès à tout le staff
            // Dans une implémentation complète, il faudrait vérifier si le patient
            // appartient au même laboratoire que le staff
            log.debug("Staff access granted to patient {} (basic implementation)", patientId);
            return true;
        }

        log.debug("Access denied to patient {} for user {}", patientId, getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut lire tous les patients
     */
    public boolean canReadAllPatients() {
        log.debug("Checking read all patients permission for user {}", getCurrentUserId());

        // Les admins peuvent lire tous les patients
        if (isCurrentUserAdmin()) {
            log.debug("Admin can read all patients");
            return true;
        }

        // Le staff peut lire les patients de leur laboratoire
        if (isCurrentUserStaff()) {
            log.debug("Staff can read patients in their laboratory");
            return true;
        }

        log.debug("Read all patients denied for user {}", getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut écrire/modifier des données patient
     */
    public boolean canWritePatient() {
        log.debug("Checking write patient permission for user {}", getCurrentUserId());

        // Les admins peuvent écrire
        if (isCurrentUserAdmin()) {
            log.debug("Admin can write patient data");
            return true;
        }

        // Le staff avec les bons rôles peut écrire
        if (isCurrentUserStaff()) {
            String role = getCurrentUserRole();
            boolean canWrite = "ADMIN_LAB".equals(role) || "SECRETAIRE".equals(role);
            log.debug("Staff write permission: {} (role: {})", canWrite, role);
            return canWrite;
        }

        log.debug("Write patient denied for user {}", getCurrentUserId());
        return false;
    }

    /**
     * Vérifie si l'utilisateur peut supprimer des patients
     */
    public boolean canDeletePatient() {
        log.debug("Checking delete patient permission for user {}", getCurrentUserId());

        // Seuls les admins peuvent supprimer
        boolean canDelete = isCurrentUserAdmin();
        log.debug("Delete patient permission: {} for user {}", canDelete, getCurrentUserId());
        return canDelete;
    }

    /**
     * Vérifie si l'utilisateur a une permission spécifique
     */
    public boolean hasPermission(String permission) {
        return hasAuthority("PERMISSION_" + permission);
    }

    /**
     * Vérifie si l'utilisateur a un rôle spécifique
     */
    public boolean hasRole(String role) {
        return hasAuthority("ROLE_" + role);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/service/PatientAuditService.java

```java
package com.lims.patient.service;

import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAuditLog;
import com.lims.patient.repository.PatientAuditLogRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service d'audit pour tracer toutes les opérations sur les patients
 * Conformité RGPD
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientAuditService {

    private final PatientAuditLogRepository auditLogRepository;

    /**
     * Log un accès général aux données patient
     */
    public void logPatientAccess(UUID patientId, String action, String description,
                                 String performedBy, String userType) {

        PatientAuditLog auditLog = PatientAuditLog.builder()
                .patientId(patientId)
                .action(action)
                .description(description)
                .performedBy(performedBy)
                .performedByType(userType)
                .clientIp(getClientIpAddress())
                .userAgent(getUserAgent())
                .result("SUCCES")
                .dateAction(LocalDateTime.now())
                .correlationId(UUID.randomUUID())
                .build();

        auditLogRepository.save(auditLog);

        log.info("Audit enregistré: {} - Patient: {} - Utilisateur: {}",
                action, patientId, performedBy);
    }

    /**
     * Log la création d'un patient
     */
    public void logPatientCreation(Patient patient, String createdBy) {
        logPatientAccess(
                patient.getId(),
                "PATIENT_CREATED",
                String.format("Nouveau patient créé: %s %s", patient.getPrenom(), patient.getNom()),
                createdBy,
                "STAFF"
        );
    }

    /**
     * Log la modification d'un patient
     */
    public void logPatientUpdate(Patient patient, String modifiedBy) {
        logPatientAccess(
                patient.getId(),
                "PATIENT_UPDATED",
                String.format("Patient modifié: %s %s", patient.getPrenom(), patient.getNom()),
                modifiedBy,
                "STAFF"
        );
    }

    /**
     * Log la suppression d'un patient
     */
    public void logPatientDeletion(Patient patient, String deletedBy) {
        logPatientAccess(
                patient.getId(),
                "PATIENT_DELETED",
                String.format("Patient supprimé (soft delete): %s %s", patient.getPrenom(), patient.getNom()),
                deletedBy,
                "STAFF"
        );
    }

    /**
     * Récupère l'adresse IP du client
     */
    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();

            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }

            return request.getRemoteAddr();
        } catch (Exception e) {
            log.warn("Impossible de récupérer l'adresse IP", e);
            return "UNKNOWN";
        }
    }

    /**
     * Récupère le User-Agent du client
     */
    private String getUserAgent() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();

            return request.getHeader("User-Agent");
        } catch (Exception e) {
            log.warn("Impossible de récupérer le User-Agent", e);
            return "UNKNOWN";
        }
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/service/PatientSearchService.java

```java
package com.lims.patient.service;

import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.entity.Patient;
import com.lims.patient.repository.PatientRepository;
import com.lims.patient.specification.PatientSpecifications;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service de recherche de patients - Version avec Specifications dynamiques
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSearchService {

    private final PatientRepository patientRepository;

    /**
     * Recherche de patients avec critères multiples - VERSION DYNAMIQUE
     * Construction dynamique de la requête selon les critères fournis
     */
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec critères: {}", request);

        // Validation et correction des paramètres de pagination
        int page = Math.max(0, request.page());
        int size = request.size();
        if (size <= 0) {
            size = 20; // Valeur par défaut
            log.debug("Taille de page corrigée de {} à {}", request.size(), size);
        }
        size = Math.min(100, size); // Limite maximale

        // Construction du tri
        Sort sort = buildSort(request.sortBy(), request.sortDirection());
        Pageable pageable = PageRequest.of(page, size, sort);

        // Déterminer si c'est une recherche exacte par email
        boolean emailExactMatch = isEmailExactSearch(request);

        log.debug("Recherche email exacte: {}", emailExactMatch);

        // Construction de la specification dynamique
        Specification<Patient> specification = PatientSpecifications.searchCriteria(
                request.nom(),
                request.prenom(),
                request.numeroSecu(),
                request.email(),
                request.telephone(),
                request.ville(),
                request.codePostal(),
                request.dateNaissance(),
                request.sexe(),
                request.statut(),
                emailExactMatch
        );

        // Exécution de la requête
        Page<Patient> patientsPage = patientRepository.findAll(specification, pageable);

        log.info("Trouvé {} patients sur {} total",
                patientsPage.getNumberOfElements(),
                patientsPage.getTotalElements());

        // Mapping vers les DTOs de réponse
        List<PatientSummaryResponse> patients = patientsPage.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());

        return PatientSearchResponse.builder()
                .patients(patients)
                .currentPage(patientsPage.getNumber())
                .totalPages(patientsPage.getTotalPages())
                .totalElements(patientsPage.getTotalElements())
                .pageSize(patientsPage.getSize())
                .build();
    }

    /**
     * Détermine si c'est une recherche exacte par email
     * (email seul ou email qui ressemble à une adresse complète)
     */
    private boolean isEmailExactSearch(PatientSearchRequest request) {
        if (request.email() == null || request.email().trim().isEmpty()) {
            return false;
        }

        String email = request.email().trim();

        // Si l'email contient @ et semble être une adresse complète, recherche exacte
        if (email.contains("@") && email.contains(".")) {
            return true;
        }

        // Si c'est le seul critère de recherche, recherche exacte aussi
        return areOtherCriteriaEmpty(request);
    }

    /**
     * Vérifie si les autres critères sont vides
     */
    private boolean areOtherCriteriaEmpty(PatientSearchRequest request) {
        return (request.nom() == null || request.nom().trim().isEmpty()) &&
                (request.prenom() == null || request.prenom().trim().isEmpty()) &&
                (request.numeroSecu() == null || request.numeroSecu().trim().isEmpty()) &&
                (request.telephone() == null || request.telephone().trim().isEmpty()) &&
                (request.ville() == null || request.ville().trim().isEmpty()) &&
                request.codePostal() == null &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
    }

    /**
     * Recherche de patients par nom et prénom
     */
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        log.info("Recherche par nom: {} et prénom: {}", nom, prenom);

        Specification<Patient> spec = PatientSpecifications.searchCriteria(
                nom, prenom, null, null, null, null, null, null, null, null, false);

        List<Patient> patients = patientRepository.findAll(spec);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Recherche rapide (typeahead)
     */
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        log.info("Recherche rapide: {}", query);

        if (query == null || query.trim().length() < 2) {
            return List.of();
        }

        // Recherche dans nom, prénom ou email
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.hasNom(query)
                        .or(PatientSpecifications.hasPrenom(query))
                        .or(PatientSpecifications.hasEmailContaining(query)));

        // Pagination pour limiter les résultats
        Pageable pageable = PageRequest.of(0, limit, Sort.by("dateCreation").descending());
        Page<Patient> patients = patientRepository.findAll(spec, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Construit l'objet Sort pour la pagination
     */
    private Sort buildSort(String sortBy, String sortDirection) {
        String[] allowedSortFields = {
                "nom", "prenom", "dateNaissance", "ville", "email",
                "telephone", "dateCreation", "dateModification", "statut"
        };

        String validSortBy = "dateCreation"; // Par défaut
        if (sortBy != null && List.of(allowedSortFields).contains(sortBy)) {
            validSortBy = sortBy;
        }

        Sort.Direction direction = Sort.Direction.DESC; // Par défaut
        if ("ASC".equalsIgnoreCase(sortDirection)) {
            direction = Sort.Direction.ASC;
        }

        return Sort.by(direction, validSortBy);
    }

    /**
     * Mappe un Patient vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(patient.getNomComplet())
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(patient.getAge())
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    // ===== AUTRES MÉTHODES (inchangées) =====

    public long countActivePatients() {
        return patientRepository.countActivePatients();
    }

    public List<Object[]> getPatientStatisticsByStatus() {
        return patientRepository.countPatientsByStatus();
    }

    public List<Object[]> getPatientStatisticsByGender() {
        return patientRepository.countPatientsByGender();
    }

    public List<Object[]> getPatientStatisticsByCity() {
        return patientRepository.countPatientsByCity();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/service/PatientService.java

```java
package com.lims.patient.service;

import com.lims.patient.dto.request.*;
import com.lims.patient.dto.response.*;
import com.lims.patient.entity.Patient;
import com.lims.patient.entity.PatientAssurance;
import com.lims.patient.enums.PatientStatus;
import com.lims.patient.exception.DuplicatePatientException;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.exception.PatientNotFoundException;
import com.lims.patient.repository.PatientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service principal pour la gestion des patients - Version centralisée
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientService {

    private final PatientRepository patientRepository;
    private final PatientSearchService patientSearchService;

    /**
     * Crée un nouveau patient avec structure centralisée
     */
    public PatientResponse createPatient(CreatePatientRequest request) {
        log.info("Création d'un nouveau patient: {} {}",
                request.personalInfo().prenom(), request.personalInfo().nom());

        // 1. Validation des données
        validateCreateRequest(request);

        // 2. Vérification des doublons
        checkForDuplicates(request);

        // 3. Construction de l'entité Patient
        Patient patient = buildPatientFromRequest(request);

        // 4. Ajout des assurances
        if (request.insurances() != null) {
            for (InsuranceRequest insuranceRequest : request.insurances()) {
                PatientAssurance assurance = buildAssuranceFromRequest(insuranceRequest);
                patient.addAssurance(assurance);
            }
        }

        // 5. Sauvegarde
        patient = patientRepository.save(patient);

        log.info("Patient créé avec succès: ID={}", patient.getId());
        return mapToResponse(patient);
    }

    /**
     * Met à jour un patient existant
     */
    public PatientResponse updatePatient(UUID patientId, UpdatePatientRequest request) {
        log.info("Mise à jour du patient: {}", patientId);

        Patient patient = getPatientById(patientId);

        // Validation de la mise à jour
        validateUpdateRequest(request, patient);

        // Mise à jour des informations personnelles
        if (request.personalInfo() != null) {
            updatePersonalInfo(patient, request.personalInfo());
        }

        // Mise à jour des informations de contact
        if (request.contactInfo() != null) {
            updateContactInfo(patient, request.contactInfo());
        }

        // Mise à jour des consentements
        if (request.consent() != null) {
            updateConsent(patient, request.consent());
        }

        // Mise à jour des assurances
        if (request.insurances() != null) {
            updateInsurances(patient, request.insurances());
        }

        patient = patientRepository.save(patient);
        log.info("Patient mis à jour avec succès: {}", patientId);

        return mapToResponse(patient);
    }

    /**
     * Recherche un patient par ID
     */
    @Transactional(readOnly = true)
    public PatientResponse getPatient(UUID patientId) {
        Patient patient = getPatientById(patientId);
        return mapToResponse(patient);
    }

    /**
     * Suppression logique d'un patient
     */
    public void deletePatient(UUID patientId) {
        log.info("Suppression du patient: {}", patientId);

        Patient patient = getPatientById(patientId);
        patient.setStatut(PatientStatus.INACTIF);
        patient.setDateSuppression(LocalDateTime.now());

        patientRepository.save(patient);
        log.info("Patient supprimé avec succès: {}", patientId);
    }

    /**
     * Recherche de patients avec critères multiples
     */
    @Transactional(readOnly = true)
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec les critères: {}", request);
        return patientSearchService.searchPatients(request);
    }

    /**
     * Recherche par email
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByEmail(String email) {
        return patientRepository.findByEmailIgnoreCaseAndDateSuppressionIsNull(email)
                .map(this::mapToResponse);
    }

    /**
     * Recherche par téléphone
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByTelephone(String telephone) {
        return patientRepository.findByTelephoneAndDateSuppressionIsNull(telephone)
                .map(this::mapToResponse);
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByNumeroSecu(String numeroSecu) {
        return patientRepository.findByNumeroSecuAndDateSuppressionIsNull(numeroSecu)
                .map(this::mapToResponse);
    }

    /**
     * Obtient tous les patients actifs
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> getActivePatients(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("dateCreation").descending());
        Page<Patient> patients = patientRepository.findByStatutAndDateSuppressionIsNull(
                PatientStatus.ACTIF, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    // ============================================
    // MÉTHODES PRIVÉES
    // ============================================

    /**
     * Récupère un patient par ID ou lance une exception
     */
    private Patient getPatientById(UUID patientId) {
        return patientRepository.findByIdAndDateSuppressionIsNull(patientId)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + patientId));
    }

    /**
     * Validation de la requête de création
     */
    private void validateCreateRequest(CreatePatientRequest request) {
        if (request == null) {
            throw new InvalidPatientDataException("La requête de création ne peut pas être nulle");
        }

        if (request.personalInfo() == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        if (request.contactInfo() == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        if (request.consent() == null) {
            throw new InvalidPatientDataException("Les consentements sont obligatoires");
        }

        // Validation du consentement obligatoire
        if (!request.consent().consentementCreationCompte()) {
            throw new InvalidPatientDataException("Le consentement de création de compte est obligatoire");
        }
    }

    /**
     * Validation de la requête de mise à jour
     */
    private void validateUpdateRequest(UpdatePatientRequest request, Patient patient) {
        if (request == null) {
            throw new InvalidPatientDataException("La requête de mise à jour ne peut pas être nulle");
        }

        // Validation que le patient peut être modifié
        if (patient.getStatut() == PatientStatus.DECEDE) {
            throw new InvalidPatientDataException("Impossible de modifier un patient décédé");
        }
    }

    /**
     * Vérification des doublons
     */
    private void checkForDuplicates(CreatePatientRequest request) {
        // Vérification par numéro de sécurité sociale
        if (patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(
                request.personalInfo().numeroSecu())) {
            throw new DuplicatePatientException("Un patient avec ce numéro de sécurité sociale existe déjà");
        }

        // Vérification par email
        if (patientRepository.existsByEmailIgnoreCaseAndDateSuppressionIsNull(
                request.contactInfo().email())) {
            throw new DuplicatePatientException("Un patient avec cet email existe déjà");
        }

        // Vérification par téléphone
        if (patientRepository.existsByTelephoneAndDateSuppressionIsNull(
                request.contactInfo().telephone())) {
            throw new DuplicatePatientException("Un patient avec ce téléphone existe déjà");
        }
    }

    /**
     * Construction de l'entité Patient depuis la requête
     */
    private Patient buildPatientFromRequest(CreatePatientRequest request) {
        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        return Patient.builder()
                // Informations personnelles
                .nom(personalInfo.nom())
                .prenom(personalInfo.prenom())
                .nomJeuneFille(personalInfo.nomJeuneFille())
                .dateNaissance(personalInfo.dateNaissance())
                .lieuNaissance(personalInfo.lieuNaissance())
                .sexe(personalInfo.sexe())
                .numeroSecu(personalInfo.numeroSecu())
                .medecinTraitant(personalInfo.medecinTraitant())
                .allergiesConnues(personalInfo.allergiesConnues())
                .antecedentsMedicaux(personalInfo.antecedentsMedicaux())

                // Informations de contact centralisées
                .email(contactInfo.email())
                .telephone(contactInfo.telephone())
                .adresseLigne1(contactInfo.adresseLigne1())
                .adresseLigne2(contactInfo.adresseLigne2())
                .codePostal(contactInfo.codePostal())
                .ville(contactInfo.ville())
                .departement(contactInfo.departement())
                .region(contactInfo.region())
                .pays(contactInfo.pays() != null ? contactInfo.pays() : "France")
                .latitude(contactInfo.latitude())
                .longitude(contactInfo.longitude())

                // Préférences de communication
                .methodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee())
                .preferenceNotification(contactInfo.preferenceNotification())
                .languePreferee(contactInfo.languePreferee() != null ? contactInfo.languePreferee() : "fr-FR")
                .notificationsResultats(contactInfo.notificationsResultats() != null ? contactInfo.notificationsResultats() : true)
                .notificationsRdv(contactInfo.notificationsRdv() != null ? contactInfo.notificationsRdv() : true)
                .notificationsRappels(contactInfo.notificationsRappels() != null ? contactInfo.notificationsRappels() : true)

                // Consentements RGPD
                .consentementCreationCompte(consent.consentementCreationCompte())
                .consentementSms(consent.consentementSms())
                .consentementEmail(consent.consentementEmail())
                .dateConsentement(consent.consentementCreationCompte() ? LocalDateTime.now() : null)

                // Métadonnées
                .statut(PatientStatus.ACTIF)
                .creePar(request.createdBy())
                .build();
    }

    /**
     * Construction d'une assurance depuis la requête
     */
    private PatientAssurance buildAssuranceFromRequest(InsuranceRequest request) {
        return PatientAssurance.builder()
                .typeAssurance(request.typeAssurance())
                .nomOrganisme(request.nomOrganisme())
                .numeroAdherent(request.numeroAdherent())
                .dateDebut(request.dateDebut())
                .dateFin(request.dateFin())
                .tiersPayantAutorise(request.tiersPayantAutorise() != null ? request.tiersPayantAutorise() : false)
                .pourcentagePriseCharge(request.pourcentagePriseCharge())
                .referenceDocument(request.referenceDocument())
                .estActive(true)
                .build();
    }

    /**
     * Met à jour les informations personnelles
     */
    private void updatePersonalInfo(Patient patient, PersonalInfoUpdateRequest personalInfo) {
        if (personalInfo.nom() != null) patient.setNom(personalInfo.nom());
        if (personalInfo.prenom() != null) patient.setPrenom(personalInfo.prenom());
        if (personalInfo.nomJeuneFille() != null) patient.setNomJeuneFille(personalInfo.nomJeuneFille());
        if (personalInfo.dateNaissance() != null) patient.setDateNaissance(personalInfo.dateNaissance());
        if (personalInfo.lieuNaissance() != null) patient.setLieuNaissance(personalInfo.lieuNaissance());
        if (personalInfo.sexe() != null) patient.setSexe(personalInfo.sexe());
        if (personalInfo.medecinTraitant() != null) patient.setMedecinTraitant(personalInfo.medecinTraitant());
        if (personalInfo.allergiesConnues() != null) patient.setAllergiesConnues(personalInfo.allergiesConnues());
        if (personalInfo.antecedentsMedicaux() != null) patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());
    }

    /**
     * Met à jour les informations de contact
     */
    private void updateContactInfo(Patient patient, ContactInfoUpdateRequest contactInfo) {
        if (contactInfo.email() != null) patient.setEmail(contactInfo.email());
        if (contactInfo.telephone() != null) patient.setTelephone(contactInfo.telephone());
        if (contactInfo.adresseLigne1() != null) patient.setAdresseLigne1(contactInfo.adresseLigne1());
        if (contactInfo.adresseLigne2() != null) patient.setAdresseLigne2(contactInfo.adresseLigne2());
        if (contactInfo.codePostal() != null) patient.setCodePostal(contactInfo.codePostal());
        if (contactInfo.ville() != null) patient.setVille(contactInfo.ville());
        if (contactInfo.departement() != null) patient.setDepartement(contactInfo.departement());
        if (contactInfo.region() != null) patient.setRegion(contactInfo.region());
        if (contactInfo.pays() != null) patient.setPays(contactInfo.pays());
        if (contactInfo.latitude() != null) patient.setLatitude(contactInfo.latitude());
        if (contactInfo.longitude() != null) patient.setLongitude(contactInfo.longitude());
        if (contactInfo.methodeLivraisonPreferee() != null) patient.setMethodeLivraisonPreferee(contactInfo.methodeLivraisonPreferee());
        if (contactInfo.preferenceNotification() != null) patient.setPreferenceNotification(contactInfo.preferenceNotification());
        if (contactInfo.languePreferee() != null) patient.setLanguePreferee(contactInfo.languePreferee());
        if (contactInfo.notificationsResultats() != null) patient.setNotificationsResultats(contactInfo.notificationsResultats());
        if (contactInfo.notificationsRdv() != null) patient.setNotificationsRdv(contactInfo.notificationsRdv());
        if (contactInfo.notificationsRappels() != null) patient.setNotificationsRappels(contactInfo.notificationsRappels());
    }

    /**
     * Met à jour les consentements
     */
    private void updateConsent(Patient patient, ConsentUpdateRequest consent) {
        if (consent.consentementSms() != null) patient.setConsentementSms(consent.consentementSms());
        if (consent.consentementEmail() != null) patient.setConsentementEmail(consent.consentementEmail());
    }

    /**
     * Met à jour les assurances
     */
    private void updateInsurances(Patient patient, List<InsuranceRequest> insurances) {
        // Suppression des anciennes assurances
        patient.getAssurances().clear();

        // Ajout des nouvelles assurances
        for (InsuranceRequest insuranceRequest : insurances) {
            PatientAssurance assurance = buildAssuranceFromRequest(insuranceRequest);
            patient.addAssurance(assurance);
        }
    }

    /**
     * Mappe un Patient vers PatientResponse
     */
    private PatientResponse mapToResponse(Patient patient) {
        return PatientResponse.builder()
                .id(patient.getId().toString())
                .personalInfo(mapToPersonalInfoResponse(patient))
                .contactInfo(mapToContactInfoResponse(patient))
                .insurances(patient.getAssurances().stream()
                        .map(this::mapToInsuranceResponse)
                        .collect(Collectors.toList()))
                .consent(mapToConsentResponse(patient))
                .metadata(mapToMetadataResponse(patient))
                .build();
    }

    /**
     * Mappe vers PersonalInfoResponse
     */
    private PersonalInfoResponse mapToPersonalInfoResponse(Patient patient) {
        return PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(patient.getNumeroSecuMasque())
                .age(patient.getAge())
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();
    }

    /**
     * Mappe vers ContactInfoResponse
     */
    private ContactInfoResponse mapToContactInfoResponse(Patient patient) {
        return ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .adresseComplete(patient.getAdresseComplete())
                .adresseLigne1(patient.getAdresseLigne1())
                .adresseLigne2(patient.getAdresseLigne2())
                .codePostal(patient.getCodePostal())
                .ville(patient.getVille())
                .departement(patient.getDepartement())
                .region(patient.getRegion())
                .pays(patient.getPays())
                .latitude(patient.getLatitude())
                .longitude(patient.getLongitude())
                .methodeLivraisonPreferee(patient.getMethodeLivraisonPreferee())
                .preferenceNotification(patient.getPreferenceNotification())
                .languePreferee(patient.getLanguePreferee())
                .notificationsResultats(patient.getNotificationsResultats())
                .notificationsRdv(patient.getNotificationsRdv())
                .notificationsRappels(patient.getNotificationsRappels())
                .build();
    }

    /**
     * Mappe vers InsuranceResponse
     */
    private InsuranceResponse mapToInsuranceResponse(PatientAssurance assurance) {
        return InsuranceResponse.builder()
                .id(assurance.getId().toString())
                .typeAssurance(assurance.getTypeAssurance())
                .nomOrganisme(assurance.getNomOrganisme())
                .numeroAdherent(assurance.getNumeroAdherent())
                .dateDebut(assurance.getDateDebut())
                .dateFin(assurance.getDateFin())
                .estActive(assurance.getEstActive())
                .tiersPayantAutorise(assurance.getTiersPayantAutorise())
                .pourcentagePriseCharge(assurance.getPourcentagePriseCharge())
                .referenceDocument(assurance.getReferenceDocument())
                .build();
    }

    /**
     * Mappe vers ConsentResponse
     */
    private ConsentResponse mapToConsentResponse(Patient patient) {
        return ConsentResponse.builder()
                .consentementCreationCompte(patient.getConsentementCreationCompte())
                .consentementSms(patient.getConsentementSms())
                .consentementEmail(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();
    }

    /**
     * Mappe vers MetadataResponse
     */
    private MetadataResponse mapToMetadataResponse(Patient patient) {
        return MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .actif(patient.isActive())
                .build();
    }

    /**
     * Mappe vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(patient.getNomComplet())
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(patient.getAge())
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/service/PatientValidationService.java

```java
package com.lims.patient.service;

import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.UpdatePatientRequest;
import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PrescriptionStatus;
import com.lims.patient.exception.InvalidPatientDataException;
import com.lims.patient.exception.ConsentValidationException;
import com.lims.patient.exception.PatientBusinessRuleException;
import com.lims.patient.repository.PatientRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.Period;
import java.util.regex.Pattern;

/**
 * Service de validation des règles métier pour les patients - Version centralisée
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PatientValidationService {

    private final PatientRepository patientRepository;

    // Patterns de validation
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "^\\+[1-9][0-9]{8,14}$"
    );

    private static final Pattern CODE_POSTAL_PATTERN = Pattern.compile(
            "^[0-9]{5}$"
    );

    private static final Pattern NIR_PATTERN = Pattern.compile(
            "^[12][0-9]{12}[0-9]{2}$"
    );

    /**
     * Valide les données d'un nouveau patient avec structure centralisée
     */
    public void validateNewPatient(CreatePatientRequest request) {
        log.debug("Validation des données du nouveau patient");

        if (request == null) {
            throw new InvalidPatientDataException("La requête de création ne peut pas être nulle");
        }

        // Validation des informations personnelles
        validatePersonalInfo(request);

        // Validation des informations de contact centralisées
        validateContactInfo(request);

        // Validation des consentements RGPD
        validateConsents(request);

        // Validation des assurances si présentes
        if (request.insurances() != null && !request.insurances().isEmpty()) {
            validateInsurances(request);
        }

        log.debug("Validation du nouveau patient terminée avec succès");
    }

    /**
     * Valide les modifications d'un patient existant
     */
    public void validatePatientUpdate(Patient existingPatient, UpdatePatientRequest request) {
        log.debug("Validation des modifications du patient {}", existingPatient.getId());

        if (existingPatient == null) {
            throw new InvalidPatientDataException("Le patient existant ne peut pas être nul");
        }

        if (request == null) {
            throw new InvalidPatientDataException("La requête de mise à jour ne peut pas être nulle");
        }

        // Validation des informations personnelles si modifiées
        if (request.personalInfo() != null) {
            validatePersonalInfoUpdate(request.personalInfo(), existingPatient);
        }

        // Validation des informations de contact si modifiées
        if (request.contactInfo() != null) {
            validateContactInfoUpdate(request.contactInfo());
        }

        // Validation des consentements si modifiés
        if (request.consent() != null) {
            validateConsentUpdate(request.consent(), existingPatient);
        }

        log.debug("Validation des modifications terminée avec succès");
    }

    /**
     * Valide la suppression d'un patient
     */
    public void validatePatientDeletion(Patient patient) {
        log.debug("Validation de la suppression du patient {}", patient.getId());

        if (patient == null) {
            throw new InvalidPatientDataException("Le patient à supprimer ne peut pas être nul");
        }

        // Vérifier s'il y a des ordonnances actives
        boolean hasActivePrescriptions = patient.getOrdonnances().stream()
                .anyMatch(ordonnance -> ordonnance.getDateSuppression() == null &&
                        (ordonnance.getStatut() == PrescriptionStatus.EN_ATTENTE ||
                                ordonnance.getStatut() == PrescriptionStatus.VALIDEE));

        if (hasActivePrescriptions) {
            throw new PatientBusinessRuleException(
                    "SUPPRESSION_INTERDITE",
                    "Impossible de supprimer le patient : il a des ordonnances actives");
        }

        // Vérification des assurances actives
        boolean hasActiveInsurance = patient.getAssurances().stream()
                .anyMatch(assurance -> assurance.getEstActive() != null &&
                        assurance.getEstActive() &&
                        (assurance.getDateFin() == null || assurance.getDateFin().isAfter(LocalDate.now())));

        if (hasActiveInsurance) {
            log.warn("Suppression d'un patient avec assurance active: {}", patient.getId());
        }

        log.debug("Validation de suppression terminée avec succès");
    }

    // ============================================
    // MÉTHODES PRIVÉES DE VALIDATION
    // ============================================

    /**
     * Valide les informations personnelles lors de la création
     */
    private void validatePersonalInfo(CreatePatientRequest request) {
        var personalInfo = request.personalInfo();

        if (personalInfo == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        // Validation des champs obligatoires
        if (!StringUtils.hasText(personalInfo.nom())) {
            throw new InvalidPatientDataException("Le nom est obligatoire");
        }

        if (!StringUtils.hasText(personalInfo.prenom())) {
            throw new InvalidPatientDataException("Le prénom est obligatoire");
        }

        if (personalInfo.dateNaissance() == null) {
            throw new InvalidPatientDataException("La date de naissance est obligatoire");
        }

        if (personalInfo.sexe() == null) {
            throw new InvalidPatientDataException("Le sexe est obligatoire");
        }

        if (!StringUtils.hasText(personalInfo.numeroSecu())) {
            throw new InvalidPatientDataException("Le numéro de sécurité sociale est obligatoire");
        }

        // Validation de l'âge
        validateAge(personalInfo.dateNaissance());

        // Validation du NIR
        validateNIR(personalInfo.numeroSecu(), personalInfo.dateNaissance(), personalInfo.sexe());
    }

    /**
     * Valide les informations de contact centralisées lors de la création
     */
    private void validateContactInfo(CreatePatientRequest request) {
        var contactInfo = request.contactInfo();

        if (contactInfo == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        // Validation email obligatoire
        if (!StringUtils.hasText(contactInfo.email())) {
            throw new InvalidPatientDataException("L'email est obligatoire");
        }

        if (!EMAIL_PATTERN.matcher(contactInfo.email()).matches()) {
            throw new InvalidPatientDataException("Format d'email invalide: " + contactInfo.email());
        }

        // Validation téléphone obligatoire
        if (!StringUtils.hasText(contactInfo.telephone())) {
            throw new InvalidPatientDataException("Le téléphone est obligatoire");
        }

        if (!PHONE_PATTERN.matcher(contactInfo.telephone()).matches()) {
            throw new InvalidPatientDataException("Format de téléphone invalide: " + contactInfo.telephone());
        }

        // Validation adresse obligatoire
        if (!StringUtils.hasText(contactInfo.adresseLigne1())) {
            throw new InvalidPatientDataException("L'adresse (ligne 1) est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.codePostal())) {
            throw new InvalidPatientDataException("Le code postal est obligatoire");
        }

        if (!CODE_POSTAL_PATTERN.matcher(contactInfo.codePostal()).matches()) {
            throw new InvalidPatientDataException("Format de code postal invalide: " + contactInfo.codePostal());
        }

        if (!StringUtils.hasText(contactInfo.ville())) {
            throw new InvalidPatientDataException("La ville est obligatoire");
        }
    }

    /**
     * Valide les consentements RGPD
     */
    private void validateConsents(CreatePatientRequest request) {
        var consent = request.consent();

        if (consent == null) {
            throw new ConsentValidationException("Les consentements sont obligatoires");
        }

        // Consentement de création de compte obligatoire
        if (consent.consentementCreationCompte() == null || !consent.consentementCreationCompte()) {
            throw new ConsentValidationException(
                    "CREATION_COMPTE",
                    "Le consentement pour la création de compte est obligatoire");
        }

        // Validation cohérence consentements
        if (consent.consentementEmail() != null && consent.consentementEmail()) {
            // Si consentement email, vérifier que l'email est valide
            if (!StringUtils.hasText(request.contactInfo().email())) {
                throw new ConsentValidationException(
                        "EMAIL",
                        "Impossible de donner le consentement email sans adresse email valide");
            }
        }

        if (consent.consentementSms() != null && consent.consentementSms()) {
            // Si consentement SMS, vérifier que le téléphone est valide
            if (!StringUtils.hasText(request.contactInfo().telephone())) {
                throw new ConsentValidationException(
                        "SMS",
                        "Impossible de donner le consentement SMS sans numéro de téléphone valide");
            }
        }
    }

    /**
     * Valide les assurances
     */
    private void validateInsurances(CreatePatientRequest request) {
        request.insurances().forEach(insurance -> {
            if (!StringUtils.hasText(insurance.nomOrganisme())) {
                throw new InvalidPatientDataException("Le nom de l'organisme d'assurance est obligatoire");
            }

            if (!StringUtils.hasText(insurance.numeroAdherent())) {
                throw new InvalidPatientDataException("Le numéro d'adhérent est obligatoire");
            }

            if (insurance.dateDebut() == null) {
                throw new InvalidPatientDataException("La date de début d'assurance est obligatoire");
            }

            if (insurance.dateDebut().isAfter(LocalDate.now())) {
                throw new InvalidPatientDataException("La date de début d'assurance ne peut pas être dans le futur");
            }

            if (insurance.dateFin() != null && insurance.dateFin().isBefore(insurance.dateDebut())) {
                throw new InvalidPatientDataException("La date de fin d'assurance doit être postérieure à la date de début");
            }
        });
    }

    /**
     * Valide l'âge du patient
     */
    private void validateAge(LocalDate dateNaissance) {
        if (dateNaissance.isAfter(LocalDate.now())) {
            throw new InvalidPatientDataException("La date de naissance ne peut pas être dans le futur");
        }

        int age = Period.between(dateNaissance, LocalDate.now()).getYears();

        if (age > 120) {
            throw new InvalidPatientDataException("L'âge du patient semble irréaliste (plus de 120 ans)");
        }
    }

    /**
     * Valide le format et la cohérence du NIR
     */
    private void validateNIR(String nir, LocalDate dateNaissance, GenderType sexe) {
        if (!StringUtils.hasText(nir)) {
            throw new InvalidPatientDataException("Le NIR est obligatoire");
        }

        // Normalisation (suppression des espaces)
        String normalizedNir = nir.replaceAll("\\s", "");

        if (!NIR_PATTERN.matcher(normalizedNir).matches()) {
            throw new InvalidPatientDataException("Format NIR invalide. Attendu: 13 chiffres + 2 chiffres de contrôle");
        }

        // Vérification du sexe (1er chiffre : 1=homme, 2=femme)
        char firstDigit = normalizedNir.charAt(0);
        if (sexe == GenderType.M && firstDigit != '1') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (homme)");
        }
        if (sexe == GenderType.F && firstDigit != '2') {
            throw new InvalidPatientDataException("NIR incohérent avec le sexe déclaré (femme)");
        }

        // Vérification de l'année de naissance (2 chiffres suivants)
        try {
            int yearFromNir = Integer.parseInt(normalizedNir.substring(1, 3));
            int actualYear = dateNaissance.getYear() % 100;

            if (yearFromNir != actualYear) {
                throw new InvalidPatientDataException("NIR incohérent avec la date de naissance");
            }
        } catch (NumberFormatException e) {
            throw new InvalidPatientDataException("Format NIR invalide (année de naissance)");
        }

        // Vérification du mois de naissance (2 chiffres suivants)
        try {
            int monthFromNir = Integer.parseInt(normalizedNir.substring(3, 5));
            int actualMonth = dateNaissance.getMonthValue();

            if (monthFromNir != actualMonth) {
                throw new InvalidPatientDataException("NIR incohérent avec le mois de naissance");
            }
        } catch (NumberFormatException e) {
            throw new InvalidPatientDataException("Format NIR invalide (mois de naissance)");
        }
    }

    /**
     * Valide les modifications des informations personnelles
     */
    private void validatePersonalInfoUpdate(
            com.lims.patient.dto.request.PersonalInfoUpdateRequest personalInfo,
            Patient existingPatient) {

        // La date de naissance ne peut pas être modifiée de façon drastique
        if (personalInfo.dateNaissance() != null) {
            validateAge(personalInfo.dateNaissance());

            // Vérification que le changement n'est pas trop important (erreur de saisie)
            Period diff = Period.between(existingPatient.getDateNaissance(), personalInfo.dateNaissance());
            if (Math.abs(diff.getYears()) > 5) {
                log.warn("Modification importante de date de naissance pour patient {}: {} -> {}",
                        existingPatient.getId(), existingPatient.getDateNaissance(), personalInfo.dateNaissance());
            }
        }

        // Le sexe ne peut pas être modifié (cohérence avec NIR)
        if (personalInfo.sexe() != null && personalInfo.sexe() != existingPatient.getSexe()) {
            throw new PatientBusinessRuleException(
                    "MODIFICATION_SEXE_INTERDITE",
                    "La modification du sexe n'est pas autorisée (cohérence avec le NIR)");
        }
    }

    /**
     * Valide les modifications des informations de contact
     */
    private void validateContactInfoUpdate(
            com.lims.patient.dto.request.ContactInfoUpdateRequest contactInfo) {

        // Validation email si modifié
        if (StringUtils.hasText(contactInfo.email())) {
            if (!EMAIL_PATTERN.matcher(contactInfo.email()).matches()) {
                throw new InvalidPatientDataException("Format d'email invalide: " + contactInfo.email());
            }
        }

        // Validation téléphone si modifié
        if (StringUtils.hasText(contactInfo.telephone())) {
            if (!PHONE_PATTERN.matcher(contactInfo.telephone()).matches()) {
                throw new InvalidPatientDataException("Format de téléphone invalide: " + contactInfo.telephone());
            }
        }

        // Validation code postal si modifié
        if (StringUtils.hasText(contactInfo.codePostal())) {
            if (!CODE_POSTAL_PATTERN.matcher(contactInfo.codePostal()).matches()) {
                throw new InvalidPatientDataException("Format de code postal invalide: " + contactInfo.codePostal());
            }
        }
    }

    /**
     * Valide les modifications des consentements
     */
    private void validateConsentUpdate(
            com.lims.patient.dto.request.ConsentUpdateRequest consent,
            Patient existingPatient) {

        // Le consentement de création de compte ne peut pas être retiré
        if (consent.consentementEmail() != null || consent.consentementSms() != null) {
            if (!existingPatient.getConsentementCreationCompte()) {
                throw new ConsentValidationException(
                        "CREATION_COMPTE",
                        "Impossible de modifier les consentements sans consentement de création de compte");
            }
        }
    }

    /**
     * Valide l'unicité des données critiques
     */
    public void validateUniqueness(String numeroSecu, String email, String telephone, String excludePatientId) {
        // Vérification NIR unique
        if (StringUtils.hasText(numeroSecu)) {
            boolean nirExists = patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(numeroSecu);
            if (nirExists) {
                throw new InvalidPatientDataException("Un patient avec ce numéro de sécurité sociale existe déjà");
            }
        }

        // Vérification email unique
        if (StringUtils.hasText(email)) {
            boolean emailExists = patientRepository.existsByEmailIgnoreCaseAndDateSuppressionIsNull(email);
            if (emailExists) {
                throw new InvalidPatientDataException("Un patient avec cet email existe déjà");
            }
        }

        // Vérification téléphone unique
        if (StringUtils.hasText(telephone)) {
            boolean phoneExists = patientRepository.existsByTelephoneAndDateSuppressionIsNull(telephone);
            if (phoneExists) {
                throw new InvalidPatientDataException("Un patient avec ce téléphone existe déjà");
            }
        }
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/specification/PatientSpecifications.java

```java
package com.lims.patient.specification;

import com.lims.patient.entity.Patient;
import com.lims.patient.enums.GenderType;
import com.lims.patient.enums.PatientStatus;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDate;

/**
 * Specifications pour construire dynamiquement les requêtes Patient
 */
public class PatientSpecifications {

    /**
     * Specification de base : patient non supprimé
     */
    public static Specification<Patient> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.isNull(root.get("dateSuppression"));
    }

    /**
     * Recherche par nom (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasNom(String nom) {
        return (root, query, criteriaBuilder) -> {
            if (nom == null || nom.trim().isEmpty()) {
                return criteriaBuilder.conjunction(); // Toujours vrai
            }
            String searchTerm = "%" + nom.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("nom")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par prénom (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasPrenom(String prenom) {
        return (root, query, criteriaBuilder) -> {
            if (prenom == null || prenom.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + prenom.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("prenom")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par email (égalité exacte, insensible à la casse)
     */
    public static Specification<Patient> hasEmail(String email) {
        return (root, query, criteriaBuilder) -> {
            if (email == null || email.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(
                    criteriaBuilder.lower(root.get("email")),
                    email.toLowerCase().trim()
            );
        };
    }

    /**
     * Recherche par email partielle (recherche partielle, insensible à la casse)
     */
    public static Specification<Patient> hasEmailContaining(String email) {
        return (root, query, criteriaBuilder) -> {
            if (email == null || email.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + email.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("email")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par téléphone (recherche partielle)
     */
    public static Specification<Patient> hasTelephone(String telephone) {
        return (root, query, criteriaBuilder) -> {
            if (telephone == null || telephone.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + telephone.trim() + "%";
            return criteriaBuilder.like(root.get("telephone"), searchTerm);
        };
    }

    /**
     * Recherche par ville (insensible à la casse, recherche partielle)
     */
    public static Specification<Patient> hasVille(String ville) {
        return (root, query, criteriaBuilder) -> {
            if (ville == null || ville.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            String searchTerm = "%" + ville.toLowerCase().trim() + "%";
            return criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("ville")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par code postal (égalité exacte)
     */
    public static Specification<Patient> hasCodePostal(String codePostal) {
        return (root, query, criteriaBuilder) -> {
            if (codePostal == null || codePostal.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("codePostal"), codePostal.trim());
        };
    }

    /**
     * Recherche par date de naissance (égalité exacte)
     */
    public static Specification<Patient> hasDateNaissance(LocalDate dateNaissance) {
        return (root, query, criteriaBuilder) -> {
            if (dateNaissance == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("dateNaissance"), dateNaissance);
        };
    }

    /**
     * Recherche par sexe
     */
    public static Specification<Patient> hasSexe(GenderType sexe) {
        return (root, query, criteriaBuilder) -> {
            if (sexe == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("sexe"), sexe);
        };
    }

    /**
     * Recherche par statut
     */
    public static Specification<Patient> hasStatut(PatientStatus statut) {
        return (root, query, criteriaBuilder) -> {
            if (statut == null) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("statut"), statut);
        };
    }

    /**
     * Recherche par numéro de sécurité sociale
     */
    public static Specification<Patient> hasNumeroSecu(String numeroSecu) {
        return (root, query, criteriaBuilder) -> {
            if (numeroSecu == null || numeroSecu.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("numeroSecu"), numeroSecu.trim());
        };
    }

    /**
     * Combine toutes les specifications pour la recherche multicritères
     */
    public static Specification<Patient> searchCriteria(
            String nom,
            String prenom,
            String numeroSecu,
            String email,
            String telephone,
            String ville,
            String codePostal,
            LocalDate dateNaissance,
            GenderType sexe,
            PatientStatus statut,
            boolean emailExactMatch) {

        return Specification.where(notDeleted())
                .and(hasNom(nom))
                .and(hasPrenom(prenom))
                .and(hasNumeroSecu(numeroSecu))
                .and(emailExactMatch ? hasEmail(email) : hasEmailContaining(email))
                .and(hasTelephone(telephone))
                .and(hasVille(ville))
                .and(hasCodePostal(codePostal))
                .and(hasDateNaissance(dateNaissance))
                .and(hasSexe(sexe))
                .and(hasStatut(statut));
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/validation/NIRValidator.java

```java
package com.lims.patient.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

/**
 * Validateur pour le NIR (Numéro de Sécurité Sociale français)
 * Vérifie le format et la clé de contrôle
 */
@Component
public class NIRValidator implements ConstraintValidator<ValidNIR, String> {

    @Override
    public void initialize(ValidNIR constraintAnnotation) {
        // Initialisation si nécessaire
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }

        // Suppression des espaces et caractères de formatage
        String nir = value.replaceAll("[\\s-]", "");

        // Vérification du format : 15 chiffres
        if (!nir.matches("^[12][0-9]{12}[0-9]{2}$")) {
            return false;
        }

        // Extraction des parties
        String nirBase = nir.substring(0, 13); // 13 premiers chiffres
        String cleControle = nir.substring(13, 15); // 2 derniers chiffres

        // Calcul de la clé de contrôle
        try {
            long nirNumber = Long.parseLong(nirBase);
            int cleCalculee = 97 - (int)(nirNumber % 97);
            int cleAttendue = Integer.parseInt(cleControle);

            return cleCalculee == cleAttendue;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/validation/ValidNIR.java

```java
package com.lims.patient.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

/**
 * Annotation pour valider le format du NIR (Numéro de Sécurité Sociale français)
 */
@Documented
@Constraint(validatedBy = NIRValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidNIR {
    String message() default "Le numéro de sécurité sociale n'est pas valide";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
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

  # Database configuration
  datasource:
    url: jdbc:postgresql://localhost:5432/lims_db
    username: lims_user
    password: dev_password_123
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: LIMS-Patient-Pool
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000

  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: validate  # En production: validate
      default_schema: lims_patient
    show-sql: false  # true en développement
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
        generate_statistics: false

  # Redis configuration pour le cache
  redis:
    host: localhost
    port: 6379
    password:
    timeout: 2000ms
    jedis:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0
        max-wait: -1ms

  # Cache configuration
  cache:
    type: redis
    redis:
      time-to-live: 300000 # 5 minutes

# Configuration de sécurité - Support multi-realms
security:
  oauth2:
    resourceserver:
      jwt:
        # Configuration pour les vérifications JWT multi-realms
        # Le décodeur sera configuré programmatiquement pour supporter plusieurs realms
        keycloak:
          base-url: http://auth.lims.local
          realms:
            - name: lims-admin
              issuer-uri: http://auth.lims.local/realms/lims-admin
              jwk-set-uri: http://auth.lims.local/realms/lims-admin/protocol/openid-connect/certs
            - name: lims-patient
              issuer-uri: http://auth.lims.local/realms/lims-patient
              jwk-set-uri: http://auth.lims.local/realms/lims-patient/protocol/openid-connect/certs
            - name: lims-staff
              issuer-uri: http://auth.lims.local/realms/lims-staff
              jwk-set-uri: http://auth.lims.local/realms/lims-staff/protocol/openid-connect/certs

# Configuration métier du service patient
lims:
  jwt:
    secrets:
      # IMPORTANT: Utiliser la MÊME clé que dans lims-auth-service
      # Cette clé doit être identique à celle utilisée pour signer les JWT
      admin: "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU="
      patient: "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWP ah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU="
      staff: "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU="
  patient:
    # Règles métier
    business-rules:
      max-contacts-par-type: 3
      max-adresses-par-type: 2
      max-assurances-par-patient: 5
      validation-email-obligatoire: true
      validation-telephone-obligatoire: false
      duree-conservation-audit-jours: 2555
      soft-delete-uniquement: true

    # Configuration audit
    audit:
      enabled: true
      log-all-access: true
      retention-days: 2555
      include-ip-address: true
      include-user-agent: true

    # Configuration sécurité spécifique
    security:
      # Définir quels types d'utilisateurs peuvent accéder aux données patients
      allowed-user-types:
        - ADMIN    # Admins système (realm lims-admin)
        - PATIENT  # Patients eux-mêmes (realm lims-patient)
        - STAFF    # Personnel laboratoire (realm lims-staff)

      # Permissions par type d'utilisateur
      permissions:
        ADMIN:
          - READ_ALL_PATIENTS
          - WRITE_ALL_PATIENTS
          - DELETE_PATIENTS
          - ADMIN_OPERATIONS
        PATIENT:
          - READ_OWN_DATA
          - UPDATE_OWN_CONTACT
        STAFF:
          - READ_PATIENTS_IN_LAB
          - WRITE_PATIENTS_IN_LAB
          - SCHEDULE_APPOINTMENTS

# Logging
logging:
  level:
    com.lims.patient: DEBUG
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: DEBUG
    org.springframework.web.filter.CommonsRequestLoggingFilter: DEBUG
    root: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"

# Monitoring et management
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
      show-components: always
  metrics:
    export:
      prometheus:
        enabled: true
  info:
    env:
      enabled: true

# Configuration Swagger/OpenAPI
springdoc:
  api-docs:
    enabled: true
    path: /api-docs
  swagger-ui:
    enabled: true
    path: /swagger-ui.html
    config-url: /api-docs/swagger-config
    urls-primary-name: "Patient Service API"
    display-request-duration: true
    show-extensions: true
    show-common-extensions: true
```

# logs/lims-patient-service.log

```log
2025-07-08 01:04:41 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=52m41s303ms).
2025-07-08 02:13:07 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h8m25s358ms).
2025-07-08 03:55:53 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h42m46s195ms).
2025-07-08 05:36:17 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h40m24s333ms).
2025-07-08 06:11:13 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=34m55s478ms).
2025-07-08 07:15:42 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h4m29s45ms).
2025-07-08 07:19:06 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=3m24s496ms).
2025-07-08 07:30:37 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=10m30s174ms).
2025-07-08 07:46:34 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=15m27s761ms).
2025-07-08 08:52:31 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h4m26s637ms).
2025-07-08 10:33:09 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h40m38s252ms).
2025-07-08 11:57:49 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h24m39s929ms).
2025-07-08 13:35:02 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1h37m13s239ms).
2025-07-08 14:02:23 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=27m20s675ms).
2025-07-08 14:05:10 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=1m16s616ms).
2025-07-08 14:12:01 [LIMS-Patient-Pool housekeeper] WARN  com.zaxxer.hikari.pool.HikariPool - LIMS-Patient-Pool - Thread starvation or clock leap detected (housekeeper delta=6m51s524ms).
2025-07-08 14:41:55 [SpringApplicationShutdownHook] INFO  o.s.o.j.LocalContainerEntityManagerFactoryBean - Closing JPA EntityManagerFactory for persistence unit 'default'
2025-07-08 14:41:55 [SpringApplicationShutdownHook] INFO  com.zaxxer.hikari.HikariDataSource - LIMS-Patient-Pool - Shutdown initiated...
2025-07-08 14:41:55 [SpringApplicationShutdownHook] INFO  com.zaxxer.hikari.HikariDataSource - LIMS-Patient-Pool - Shutdown completed.

```

# logs/lims-patient-service.log.2025-07-07.0.gz

This is a binary file of the type: Binary

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

