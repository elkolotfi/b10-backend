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

import com.lims.patient.dto.error.ErrorResponse;
import com.lims.patient.dto.request.CreatePatientRequest;
import com.lims.patient.dto.request.PatientSearchRequest;
import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.dto.response.PatientSearchResponse;
import com.lims.patient.dto.response.PatientSummaryResponse;
import com.lims.patient.service.PatientAuditService;
import com.lims.patient.service.PatientSearchService;
import com.lims.patient.service.PatientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/patients")
@RequiredArgsConstructor
@Slf4j
@Validated
@Tag(name = "Patients", description = "Gestion des patients")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PatientController {
    private final PatientAuditService auditService;
    private final PatientService patientService;
    private final PatientSearchService patientSearchService;

    /**
     * Crée un nouveau patient avec toutes ses informations
     */
    @PostMapping
    @Operation(summary = "Créer un nouveau patient",
            description = "Crée un patient complet avec données personnelles, contact, assurances, spécificités et commentaire")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Patient créé avec succès",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class))),
            @ApiResponse(responseCode = "400", description = "Données invalides",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "Patient déjà existant (NIR/email/téléphone)",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientResponse> createPatient(
            @Valid @RequestBody CreatePatientRequest request,
            Authentication authentication) {

        log.info("Création d'un nouveau patient: {} {} par {}",
                request.personalInfo().prenom(),
                request.personalInfo().nom(),
                authentication.getName());

        // Passer directement la requête + créateur séparément
        PatientResponse response = patientService.createPatient(request, authentication.getName());

        // Audit simple
        /*auditService.logPatientCreation(
                response,
                authentication.getName()
        );*/

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Recherche multicritères de patients (POST recommandé)
     */
    @PostMapping("/search")
    @Operation(summary = "Recherche multicritères de patients",
            description = "Recherche avancée avec support du nom complet ou nom/prénom séparés")
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
     * Recherche rapide par nom complet (GET)
     */
    @GetMapping("/search/quick")
    @Operation(summary = "Recherche rapide par nom complet",
            description = "Recherche rapide limitée à 10 résultats pour autocomplétion")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche rapide"),
            @ApiResponse(responseCode = "400", description = "Paramètre de recherche invalide")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<PatientSummaryResponse>> quickSearch(
            @Parameter(description = "Nom complet à rechercher (nom et/ou prénom)")
            @RequestParam @Size(min = 2, max = 100, message = "Le nom complet doit contenir entre 2 et 100 caractères")
            String nomComplet) {

        log.info("Recherche rapide par nom complet: {}", nomComplet);

        List<PatientSummaryResponse> results = patientService.quickSearchByNomComplet(nomComplet);

        return ResponseEntity.ok(results);
    }

    /**
     * Recherche par nom complet avec pagination (GET)
     */
    @GetMapping("/search/nom-complet")
    @Operation(summary = "Recherche par nom complet avec pagination",
            description = "Recherche par nom complet avec support de la pagination")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Résultats de recherche paginés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSearchResponse> searchByNomComplet(
            @Parameter(description = "Nom complet à rechercher")
            @RequestParam @Size(min = 2, max = 100) String nomComplet,

            @Parameter(description = "Numéro de page (0-based)")
            @RequestParam(defaultValue = "0") @Min(0) int page,

            @Parameter(description = "Taille de page")
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size) {

        log.info("Recherche par nom complet avec pagination: {} (page: {}, size: {})",
                nomComplet, page, size);

        PatientSearchResponse response = patientSearchService.searchByNomComplet(nomComplet, page, size);

        return ResponseEntity.ok(response);
    }

    /**
     * Autocomplétion pour le nom complet
     */
    @GetMapping("/search/suggest")
    @Operation(summary = "Suggestions pour autocomplétion",
            description = "Retourne des suggestions de noms complets pour l'autocomplétion")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des suggestions"),
            @ApiResponse(responseCode = "400", description = "Paramètre invalide")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<String>> suggestNomComplet(
            @Parameter(description = "Début du nom à rechercher (minimum 2 caractères)")
            @RequestParam @Size(min = 2, max = 50) String input) {

        log.info("Suggestion d'autocomplétion pour: {}", input);

        List<String> suggestions = patientService.suggestNomComplet(input);

        return ResponseEntity.ok(suggestions);
    }

    /**
     * Recherche par nom et prénom séparés (rétrocompatibilité)
     */
    @GetMapping("/search/nom-prenom")
    @Operation(summary = "Recherche par nom et prénom séparés",
            description = "Méthode legacy pour la recherche par nom et prénom séparés")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des patients trouvés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    @Deprecated(since = "2.0", forRemoval = false)
    public ResponseEntity<List<PatientSummaryResponse>> searchByNomPrenom(
            @Parameter(description = "Nom du patient")
            @RequestParam(required = false) @Size(max = 100) String nom,

            @Parameter(description = "Prénom du patient")
            @RequestParam(required = false) @Size(max = 100) String prenom) {

        log.info("Recherche legacy par nom: {} et prénom: {}", nom, prenom);

        List<PatientSummaryResponse> results = patientService.searchByNomPrenom(nom, prenom);

        return ResponseEntity.ok(results);
    }

    /**
     * Recherche par nom et prénom séparés (rétrocompatibilité)
     */
    @GetMapping("/search/telephone")
    @Operation(summary = "Recherche par telephone",
            description = "Méthode legacy pour la recherche par numéro de telephone")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Liste des patients trouvés"),
            @ApiResponse(responseCode = "400", description = "Paramètres invalides")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    @Deprecated(since = "2.0", forRemoval = false)
    public ResponseEntity<List<PatientSummaryResponse>> searchByPhone(
            @Parameter(description = "telephone")
            @RequestParam(value = "telephone") @Size(max = 100) String phone) {

        log.info("Recherche legacy par telephone: {}", phone);

        List<PatientSummaryResponse> results = patientService.searchByPhone(phone);

        return ResponseEntity.ok(results);
    }

    // ============================================
    // GET PATIENT BY ID
    // ============================================

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN_LAB', 'SECRETAIRE', 'PRELEVEUR', 'TECHNICIEN', 'SUPER_ADMIN') or " +
            "(hasRole('PATIENT') and @patientService.isPatientOwner(authentication.name, #id))")
    @Operation(
            summary = "Récupérer les détails d'un patient",
            description = "Récupère toutes les informations d'un patient spécifique. " +
                    "Accessible au personnel du laboratoire ou au patient lui-même."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Patient trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PatientResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Patient non trouvé",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Accès interdit - Patient ne peut accéder qu'à ses propres données"
            )
    })
    public ResponseEntity<PatientResponse> getPatientById(
            @Parameter(description = "ID du patient", required = true)
            @PathVariable(value = "id") UUID id,
            Authentication authentication) {

        log.info("Consultation du patient {} par l'utilisateur: {}", id, authentication.getName());

        // Détermination du type d'utilisateur
        String userType = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().contains("PATIENT")) ? "PATIENT" : "STAFF";

        // Audit de l'accès
        /*auditService.logPatientAccess(
                id,
                "VIEW_PATIENT",
                "Consultation des détails du patient",
                authentication.getName(),
                userType
        );*/

        PatientResponse patient = patientService.getPatient(id);

        log.info("Patient {} consulté avec succès", id);

        return ResponseEntity.ok(patient);
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/converter/DeliveryMethodConverter.java

```java
package com.lims.patient.converter;

import com.lims.patient.enums.DeliveryMethod;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.extern.slf4j.Slf4j;

@Converter(autoApply = false)
@Slf4j
public class DeliveryMethodConverter implements AttributeConverter<DeliveryMethod, String> {

    @Override
    public String convertToDatabaseColumn(DeliveryMethod attribute) {
        if (attribute == null) {
            return null;
        }
        log.debug("Converting DeliveryMethod {} to database column", attribute.name());
        return attribute.name();
    }

    @Override
    public DeliveryMethod convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return null;
        }

        try {
            DeliveryMethod result = DeliveryMethod.valueOf(dbData.toUpperCase());
            log.debug("Converting database value '{}' to DeliveryMethod {}", dbData, result);
            return result;
        } catch (IllegalArgumentException e) {
            log.warn("Valeur DeliveryMethod inconnue dans la BDD : '{}', utilisation par défaut : EMAIL", dbData);
            return DeliveryMethod.EMAIL;
        }
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
        Boolean createAccount,

        @NotNull
        Boolean sms,

        @NotNull
        Boolean email
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
import jakarta.validation.constraints.Size;
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

        @Valid
        PatientSpecificitiesRequest specificities, // Liste d'IDs seulement

        @Valid @NotNull
        ConsentRequest consent,

        @Size(max = 2000, message = "Le commentaire ne peut pas dépasser 2000 caractères")
        String commentairePatient,

        String createdBy
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
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Builder;

import java.time.LocalDate;

/**
 * DTO pour la recherche de patients
 */
@Builder
public record PatientSearchRequest(
        // Recherche par nom et prénom séparés (ancienne méthode)
        String nom,
        String prenom,

        // Recherche par nom complet (nouvelle méthode)
        String nomComplet,

        String numeroSecu,
        String email,
        String telephone,
        String ville,
        String codePostal,
        LocalDate dateNaissance,
        GenderType sexe,
        PatientStatus statut,

        @Min(0) int page,
        @Min(1) @Max(100) int size,
        String sortBy,
        String sortDirection
) {

    /**
     * Constructeur par défaut avec valeurs par défaut pour pagination
     */
    public PatientSearchRequest {
        if (page < 0) page = 0;
        if (size < 1) size = 10;
        if (size > 100) size = 100;
        if (sortBy == null || sortBy.trim().isEmpty()) sortBy = "dateCreation";
        if (sortDirection == null || (!sortDirection.equalsIgnoreCase("asc") && !sortDirection.equalsIgnoreCase("desc"))) {
            sortDirection = "desc";
        }
    }

    /**
     * Vérifie si la recherche utilise le nom complet
     */
    public boolean isNomCompletSearch() {
        return nomComplet != null && !nomComplet.trim().isEmpty();
    }

    /**
     * Vérifie si la recherche utilise nom/prénom séparés
     */
    public boolean isNomPrenomSearch() {
        return (nom != null && !nom.trim().isEmpty()) ||
                (prenom != null && !prenom.trim().isEmpty());
    }

    /**
     * Retourne les mots-clés du nom complet pour la recherche
     */
    public String[] getNomCompletKeywords() {
        if (!isNomCompletSearch()) {
            return new String[0];
        }

        return nomComplet.trim()
                .toLowerCase()
                .split("\\s+"); // Divise par un ou plusieurs espaces
    }

    /**
     * Normalise le nom complet pour la recherche
     */
    public String getNomCompletNormalized() {
        if (!isNomCompletSearch()) {
            return "";
        }

        return nomComplet.trim()
                .toLowerCase()
                .replaceAll("\\s+", " "); // Remplace les espaces multiples par un seul
    }
}
```

# lims-patient-service/src/main/java/com/lims/patient/dto/request/PatientSpecificitiesRequest.java

```java
package com.lims.patient.dto.request;

import lombok.Builder;
import java.util.List;

/**
 * DTO pour les spécificités du patient - Version minimaliste selon accords
 */
@Builder
public record PatientSpecificitiesRequest(
        List<String> specificityIds // UNIQUEMENT les IDs, pas plus
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
        Boolean createAccount,
        Boolean sms,
        Boolean email,
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
        PatientSpecificitiesResponse specificities,
        ConsentResponse consent,
        String commentairePatient
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

# lims-patient-service/src/main/java/com/lims/patient/dto/response/PatientSpecificitiesResponse.java

```java
package com.lims.patient.dto.response;

import lombok.Builder;
import java.util.List;

@Builder
public record PatientSpecificitiesResponse(
        List<String> specificityIds
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
        String numeroSecuMasque,
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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
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

    @Column(name = "specificity_ids", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Builder.Default
    private List<String> specificityIds = new ArrayList<>();

    @Column(name = "commentaire_patient", columnDefinition = "TEXT")
    private String commentairePatient;

    // ===== PRÉFÉRENCES COMMUNICATION =====
    @Enumerated(EnumType.STRING)
    @Column(name = "methode_livraison_preferee", columnDefinition = "lims_patient.delivery_method")
    private DeliveryMethod methodeLivraisonPreferee = DeliveryMethod.EMAIL;

    @Enumerated(EnumType.STRING)
    @Column(name = "preference_notification", columnDefinition = "lims_patient.notification_preference")
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

    public void setCreepar(String creepar) {
        this.creePar = creepar;
    }

    // Méthodes helper pour les spécificités
    public void addSpecificity(String specificityId) {
        if (this.specificityIds == null) {
            this.specificityIds = new ArrayList<>();
        }
        if (!this.specificityIds.contains(specificityId)) {
            this.specificityIds.add(specificityId);
        }
    }

    public void removeSpecificity(String specificityId) {
        if (this.specificityIds != null) {
            this.specificityIds.remove(specificityId);
        }
    }

    public boolean hasSpecificities() {
        return this.specificityIds != null && !this.specificityIds.isEmpty();
    }

    public int getSpecificitiesCount() {
        return this.specificityIds != null ? this.specificityIds.size() : 0;
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
    PatientResponse toPatientResponse(Patient patient);

    /**
     * Convertit une entité Patient en PatientSummaryResponse pour les listes
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "nomComplet", source = ".", qualifiedByName = "buildFullName")
    @Mapping(target = "email", source = "email")
    @Mapping(target = "telephone", source = "telephone")
    @Mapping(target = "numeroSecuMasque", source = "numeroSecuMasque")
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
                .createAccount(patient.getConsentementCreationCompte())
                .sms(patient.getConsentementSms())
                .email(patient.getConsentementEmail())
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

# lims-patient-service/src/main/java/com/lims/patient/mapper/PatientSpecificitiesMapper.java

```java
package com.lims.patient.mapper;

import com.lims.patient.dto.response.PatientResponse;
import com.lims.patient.dto.response.PatientSpecificitiesResponse;
import com.lims.patient.entity.Patient;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.List;

public interface PatientSpecificitiesMapper {
    @Named("toSpecificitiesResponse")
    default PatientSpecificitiesResponse toSpecificitiesResponse(Patient patient) {
        if (patient == null) return null;

        return PatientSpecificitiesResponse.builder()
                .specificityIds(patient.getSpecificityIds() != null ? patient.getSpecificityIds() : List.of())
                .build();
    }

    // Mapping principal
    @Mapping(target = "specificities", source = ".", qualifiedByName = "toSpecificitiesResponse")
    @Mapping(target = "commentairePatient", source = "commentairePatient") // DIRECTEMENT depuis patient
    PatientResponse toPatientResponse(Patient patient);
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
 * Repository pour les patients - Version harmonisée avec l'architecture des services
 * Supporte les Specifications pour les recherches complexes + méthodes simples optimisées
 */
@Repository
public interface PatientRepository extends JpaRepository<Patient, UUID>, JpaSpecificationExecutor<Patient> {

    // ===============================================================
    // RECHERCHES DE BASE CRITIQUES (utilisées par PatientService)
    // ===============================================================

    /**
     * Trouve un patient par ID (non supprimé)
     * Utilisé par: PatientService.getPatient()
     */
    Optional<Patient> findByIdAndDateSuppressionIsNull(UUID id);

    /**
     * Trouve un patient par numéro de sécurité sociale (non supprimé)
     * Utilisé par: PatientService.findByNumeroSecu()
     */
    Optional<Patient> findByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Trouve un patient par email (égalité exacte, insensible à la casse, non supprimé)
     * Utilisé par: PatientService.findByEmail()
     */
    Optional<Patient> findByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Version alternative pour la compatibilité (nom exact utilisé dans le service)
     */
    default Optional<Patient> findByEmailAndDateSuppressionIsNull(String email) {
        return findByEmailIgnoreCaseAndDateSuppressionIsNull(email);
    }

    /**
     * Trouve un patient par téléphone (non supprimé)
     * Utilisé par: PatientService.findByTelephone()
     */
    Optional<Patient> findByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===============================================================
    // VÉRIFICATIONS D'EXISTENCE (utilisées par PatientService)
    // ===============================================================

    /**
     * Vérifie si un patient existe avec ce numéro de sécurité sociale
     * Utilisé par: PatientService.existsByNumeroSecu()
     */
    boolean existsByNumeroSecuAndDateSuppressionIsNull(String numeroSecu);

    /**
     * Vérifie si un patient existe avec cet email (insensible à la casse)
     * Utilisé par: PatientService.existsByEmail()
     */
    boolean existsByEmailIgnoreCaseAndDateSuppressionIsNull(String email);

    /**
     * Version alternative pour la compatibilité
     */
    default boolean existsByEmailAndDateSuppressionIsNull(String email) {
        return existsByEmailIgnoreCaseAndDateSuppressionIsNull(email);
    }

    /**
     * Vérifie si un patient existe avec ce téléphone
     * Utilisé par: PatientService.existsByTelephone()
     */
    boolean existsByTelephoneAndDateSuppressionIsNull(String telephone);

    // ===============================================================
    // RECHERCHES PAR STATUT (utilisées par PatientService)
    // ===============================================================

    /**
     * Trouve tous les patients par statut avec pagination
     * Utilisé par: PatientService.getActivePatients()
     */
    Page<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut, Pageable pageable);

    /**
     * Trouve tous les patients par statut (sans pagination)
     */
    List<Patient> findByStatutAndDateSuppressionIsNull(PatientStatus statut);

    /**
     * Compte les patients par statut
     * Utilisé par: PatientService.countActivePatients()
     */
    long countByStatutAndDateSuppressionIsNull(PatientStatus statut);

    // ===============================================================
    // RECHERCHES SPÉCIALISÉES OPTIMISÉES (pour PatientSearchService)
    // ===============================================================

    /**
     * Recherche optimisée par nom (pour autocomplétion rapide)
     * Note: Les recherches complexes utilisent les Specifications
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "LOWER(p.nom) LIKE LOWER(CONCAT('%', :nom, '%')) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.nom, p.prenom")
    List<Patient> findByNomContainingIgnoreCase(@Param("nom") String nom, Pageable pageable);

    /**
     * Recherche optimisée par prénom (pour autocomplétion rapide)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "LOWER(p.prenom) LIKE LOWER(CONCAT('%', :prenom, '%')) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.prenom, p.nom")
    List<Patient> findByPrenomContainingIgnoreCase(@Param("prenom") String prenom, Pageable pageable);

    /**
     * Recherche optimisée par nom complet (concaténation nom + prénom)
     * Utilisé pour les suggestions d'autocomplétion
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "(LOWER(CONCAT(p.nom, ' ', p.prenom)) LIKE LOWER(CONCAT('%', :nomComplet, '%')) OR " +
            " LOWER(CONCAT(p.prenom, ' ', p.nom)) LIKE LOWER(CONCAT('%', :nomComplet, '%'))) AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.nom, p.prenom")
    List<Patient> findByNomCompletContaining(@Param("nomComplet") String nomComplet, Pageable pageable);

    /**
     * Recherche par ville (pour filtres rapides)
     */
    List<Patient> findByVilleContainingIgnoreCaseAndDateSuppressionIsNull(String ville);

    /**
     * Recherche par code postal (pour filtres géographiques)
     */
    List<Patient> findByCodePostalAndDateSuppressionIsNull(String codePostal);

    /**
     * Recherche par date de naissance exacte
     */
    List<Patient> findByDateNaissanceAndDateSuppressionIsNull(LocalDate dateNaissance);

    /**
     * Recherche par sexe
     */
    List<Patient> findBySexeAndDateSuppressionIsNull(GenderType sexe);

    // ===============================================================
    // RECHERCHES MÉTIER SPÉCIALISÉES
    // ===============================================================

    /**
     * Trouve les patients avec notifications activées
     * Utilisé pour les campagnes de communication
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = :statut AND " +
            "(p.consentementSms = true OR p.consentementEmail = true)")
    List<Patient> findPatientsWithNotificationsEnabled(@Param("statut") PatientStatus statut);

    /**
     * Trouve les patients par tranche d'âge
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.dateNaissance BETWEEN :dateNaissanceMin AND :dateNaissanceMax " +
            "ORDER BY p.dateNaissance DESC")
    List<Patient> findByAgeRange(@Param("dateNaissanceMin") LocalDate dateNaissanceMin,
                                 @Param("dateNaissanceMax") LocalDate dateNaissanceMax);

    /**
     * Trouve les patients créés récemment
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateCreation >= :dateLimit AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.dateCreation DESC")
    List<Patient> findRecentlyCreatedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    /**
     * Trouve les patients récemment modifiés
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateModification >= :dateLimit AND " +
            "p.dateSuppression IS NULL " +
            "ORDER BY p.dateModification DESC")
    List<Patient> findRecentlyModifiedPatients(@Param("dateLimit") LocalDateTime dateLimit);

    // ===============================================================
    // RECHERCHES GÉOGRAPHIQUES
    // ===============================================================

    /**
     * Recherche par département (basé sur le code postal)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.codePostal LIKE CONCAT(:codeDepartement, '%') AND " +
            "p.dateSuppression IS NULL")
    List<Patient> findByDepartement(@Param("codeDepartement") String codeDepartement);

    /**
     * Recherche par région
     */
    List<Patient> findByRegionAndDateSuppressionIsNull(String region);

    /**
     * Recherche par proximité géographique (si vous avez des coordonnées GPS)
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

    // ===============================================================
    // STATISTIQUES (utilisées par PatientSearchService)
    // ===============================================================

    /**
     * Compte le nombre total de patients actifs
     * Utilisé par: PatientSearchService.countActivePatients()
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL AND p.statut = 'ACTIF'")
    long countActivePatients();

    /**
     * Statistiques par statut
     * Utilisé par: PatientSearchService.getPatientStatisticsByStatus()
     */
    @Query("SELECT p.statut, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.statut")
    List<Object[]> countPatientsByStatus();

    /**
     * Statistiques par sexe
     * Utilisé par: PatientSearchService.getPatientStatisticsByGender()
     */
    @Query("SELECT p.sexe, COUNT(p) FROM Patient p WHERE p.dateSuppression IS NULL GROUP BY p.sexe")
    List<Object[]> countPatientsByGender();

    /**
     * Statistiques par ville (top 10)
     * Utilisé par: PatientSearchService.getPatientStatisticsByCity()
     */
    @Query("SELECT p.ville, COUNT(p) FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND p.ville IS NOT NULL " +
            "GROUP BY p.ville ORDER BY COUNT(p) DESC")
    List<Object[]> countPatientsByCity();

    /**
     * Statistiques par tranche d'âge
     */
    @Query("SELECT " +
            "CASE " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) < 18 THEN 'Moins de 18 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 18 AND 30 THEN '18-30 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 31 AND 50 THEN '31-50 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 51 AND 70 THEN '51-70 ans' " +
            "  ELSE 'Plus de 70 ans' " +
            "END AS trancheAge, COUNT(p) " +
            "FROM Patient p WHERE p.dateSuppression IS NULL AND p.dateNaissance IS NOT NULL " +
            "GROUP BY " +
            "CASE " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) < 18 THEN 'Moins de 18 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 18 AND 30 THEN '18-30 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 31 AND 50 THEN '31-50 ans' " +
            "  WHEN EXTRACT(YEAR FROM CURRENT_DATE) - EXTRACT(YEAR FROM p.dateNaissance) BETWEEN 51 AND 70 THEN '51-70 ans' " +
            "  ELSE 'Plus de 70 ans' " +
            "END")
    List<Object[]> countPatientsByAgeRange();

    /**
     * Statistiques d'évolution (nouveaux patients par mois)
     */
    @Query("SELECT " +
            "EXTRACT(YEAR FROM p.dateCreation) as annee, " +
            "EXTRACT(MONTH FROM p.dateCreation) as mois, " +
            "COUNT(p) as nombrePatients " +
            "FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.dateCreation >= :dateDebut " +
            "GROUP BY EXTRACT(YEAR FROM p.dateCreation), EXTRACT(MONTH FROM p.dateCreation) " +
            "ORDER BY annee DESC, mois DESC")
    List<Object[]> countNewPatientsByMonth(@Param("dateDebut") LocalDateTime dateDebut);

    // ===============================================================
    // REQUÊTES DE MAINTENANCE ET AUDIT
    // ===============================================================

    /**
     * Trouve les doublons potentiels par nom/prénom/date de naissance
     */
    @Query("SELECT p1 FROM Patient p1 WHERE EXISTS (" +
            "SELECT p2 FROM Patient p2 WHERE " +
            "p1.id != p2.id AND " +
            "p1.dateSuppression IS NULL AND p2.dateSuppression IS NULL AND " +
            "LOWER(p1.nom) = LOWER(p2.nom) AND " +
            "LOWER(p1.prenom) = LOWER(p2.prenom) AND " +
            "p1.dateNaissance = p2.dateNaissance)")
    List<Patient> findPotentialDuplicates();

    /**
     * Trouve les patients avec des données incomplètes
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "(p.email IS NULL OR p.telephone IS NULL OR p.ville IS NULL)")
    List<Patient> findPatientsWithIncompleteData();

    /**
     * Trouve les patients inactifs depuis longtemps
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "p.statut = 'INACTIF' AND " +
            "p.dateModification < :dateLimit")
    List<Patient> findLongInactivePatients(@Param("dateLimit") LocalDateTime dateLimit);

    // ===============================================================
    // MÉTHODES UTILITAIRES
    // ===============================================================

    /**
     * Compte le nombre total de patients (incluant supprimés)
     */
    @Query("SELECT COUNT(p) FROM Patient p")
    long countAllPatients();

    /**
     * Compte le nombre de patients supprimés
     */
    @Query("SELECT COUNT(p) FROM Patient p WHERE p.dateSuppression IS NOT NULL")
    long countDeletedPatients();

    /**
     * Trouve les patients créés par un utilisateur spécifique
     */
    List<Patient> findByCreeParAndDateSuppressionIsNull(String creePar);

    /**
     * Recherche full-text simple (si votre base de données le supporte)
     */
    @Query("SELECT p FROM Patient p WHERE " +
            "p.dateSuppression IS NULL AND " +
            "(LOWER(p.nom) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(p.prenom) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " LOWER(p.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            " p.telephone LIKE CONCAT('%', :searchTerm, '%') OR " +
            " LOWER(p.ville) LIKE LOWER(CONCAT('%', :searchTerm, '%')))")
    List<Patient> findByFullTextSearch(@Param("searchTerm") String searchTerm, Pageable pageable);

    // NOTE IMPORTANTE:
    // Les recherches complexes multicritères se font maintenant avec les Specifications
    // dans PatientSpecifications, ce qui offre plus de flexibilité et de performance
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

import com.lims.patient.dto.response.PatientResponse;
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
                .result("SUCCESS")
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
    public void logPatientCreation(PatientResponse patient, String createdBy) {
        logPatientAccess(
                UUID.fromString(patient.id()),
                "PATIENT_CREATED",
                String.format("Nouveau patient créé: %s %s", patient.personalInfo().prenom(), patient.personalInfo().nom()),
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
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service de recherche de patients - Version adaptée avec nomComplet et Specifications dynamiques
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSearchService {

    private final PatientRepository patientRepository;

    /**
     * Recherche de patients avec critères multiples - VERSION ADAPTÉE
     * Support du nomComplet ET des critères séparés
     */
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.info("Recherche de patients avec critères: {}", request);

        // Validation des critères - si tout est vide, retourner une page vide
        if (isEmptySearchRequest(request)) {
            log.warn("Recherche sans critères - retour d'une page vide");
            return PatientSearchResponse.builder()
                    .patients(List.of())
                    .currentPage(request.page())
                    .totalPages(0)
                    .totalElements(0L)
                    .pageSize(request.size())
                    .build();
        }

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

        // Construction de la specification selon le mode de recherche
        Specification<Patient> specification = buildSearchSpecification(request);

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
     * Construction de la specification selon le mode de recherche
     */
    private Specification<Patient> buildSearchSpecification(PatientSearchRequest request) {
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted());

        // Mode recherche par nom complet (prioritaire)
        if (request.isNomCompletSearch()) {
            log.debug("Mode recherche par nom complet: {}", request.nomComplet());
            spec = spec.and(PatientSpecifications.nomCompletAdvanced(request.nomComplet()));
        }
        // Mode recherche par nom/prénom séparés
        else if (request.isNomPrenomSearch()) {
            log.debug("Mode recherche par nom/prénom séparés: {} / {}", request.nom(), request.prenom());
            if (StringUtils.hasText(request.nom())) {
                spec = spec.and(PatientSpecifications.hasNom(request.nom()));
            }
            if (StringUtils.hasText(request.prenom())) {
                spec = spec.and(PatientSpecifications.hasPrenom(request.prenom()));
            }
        }

        // Ajout des autres critères
        spec = addOtherCriteria(spec, request);

        return spec;
    }

    /**
     * Ajoute les autres critères de recherche à la specification
     */
    private Specification<Patient> addOtherCriteria(Specification<Patient> spec, PatientSearchRequest request) {
        if (StringUtils.hasText(request.numeroSecu())) {
            spec = spec.and(PatientSpecifications.hasNumeroSecu(request.numeroSecu()));
        }

        if (StringUtils.hasText(request.email())) {
            boolean emailExactMatch = isEmailExactSearch(request);
            spec = spec.and(emailExactMatch
                    ? PatientSpecifications.hasEmail(request.email())
                    : PatientSpecifications.hasEmailContaining(request.email()));
        }

        if (StringUtils.hasText(request.telephone())) {
            spec = spec.and(PatientSpecifications.hasTelephone(request.telephone()));
        }

        if (StringUtils.hasText(request.ville())) {
            spec = spec.and(PatientSpecifications.hasVille(request.ville()));
        }

        if (StringUtils.hasText(request.codePostal())) {
            spec = spec.and(PatientSpecifications.hasCodePostal(request.codePostal()));
        }

        if (request.dateNaissance() != null) {
            spec = spec.and(PatientSpecifications.hasDateNaissance(request.dateNaissance()));
        }

        if (request.sexe() != null) {
            spec = spec.and(PatientSpecifications.hasSexe(request.sexe()));
        }

        if (request.statut() != null) {
            spec = spec.and(PatientSpecifications.hasStatut(request.statut()));
        }

        return spec;
    }

    /**
     * Recherche rapide par nom complet avec limite de résultats
     */
    public List<PatientSummaryResponse> quickSearchByNomComplet(String nomComplet) {
        log.info("Recherche rapide par nom complet: {}", nomComplet);

        if (!StringUtils.hasText(nomComplet)) {
            return List.of();
        }

        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletAdvanced(nomComplet));

        // Limiter à 10 résultats pour la recherche rapide
        Pageable pageable = PageRequest.of(0, 10, Sort.by(Sort.Direction.ASC, "nom", "prenom"));

        List<Patient> patients = patientRepository.findAll(spec, pageable).getContent();

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Recherche par nom complet avec pagination
     */
    public PatientSearchResponse searchByNomComplet(String nomComplet, int page, int size) {
        log.info("Recherche par nom complet avec pagination: {} (page: {}, size: {})", nomComplet, page, size);

        PatientSearchRequest request = PatientSearchRequest.builder()
                .nomComplet(nomComplet)
                .page(page)
                .size(size)
                .sortBy("nom")
                .sortDirection("asc")
                .build();

        return searchPatients(request);
    }

    /**
     * Suggestions d'autocomplétion pour le nom complet
     */
    public List<String> suggestNomComplet(String input) {
        if (!StringUtils.hasText(input) || input.length() < 2) {
            return List.of();
        }

        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletContains(input));

        Pageable pageable = PageRequest.of(0, 5);

        List<Patient> patients = patientRepository.findAll(spec, pageable).getContent();

        return patients.stream()
                .map(patient -> String.format("%s %s", patient.getNom(), patient.getPrenom()).trim())
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * Recherche de patients par nom et prénom (rétrocompatibilité)
     */
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        log.info("Recherche par nom: {} et prénom: {}", nom, prenom);

        PatientSearchRequest request = PatientSearchRequest.builder()
                .nom(nom)
                .prenom(prenom)
                .page(0)
                .size(50)
                .sortBy("nom")
                .sortDirection("asc")
                .build();

        return searchPatients(request).patients();
    }

    public List<PatientSummaryResponse> searchByPhone(String phone) {
        log.info("Recherche par telephone: {}", phone);

        PatientSearchRequest request = PatientSearchRequest.builder()
                .telephone(phone)
                .build();

        return searchPatients(request).patients();
    }

    /**
     * Recherche rapide (typeahead) - version adaptée
     */
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        log.info("Recherche rapide: {}", query);

        if (query == null || query.trim().length() < 2) {
            return List.of();
        }

        // Recherche dans nom complet, nom, prénom ou email
        Specification<Patient> spec = Specification.where(PatientSpecifications.notDeleted())
                .and(PatientSpecifications.nomCompletContains(query)
                        .or(PatientSpecifications.hasNom(query))
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
     * Vérifie si la requête de recherche est complètement vide
     */
    private boolean isEmptySearchRequest(PatientSearchRequest request) {
        return !request.isNomCompletSearch() &&
                !request.isNomPrenomSearch() &&
                !StringUtils.hasText(request.numeroSecu()) &&
                !StringUtils.hasText(request.email()) &&
                !StringUtils.hasText(request.telephone()) &&
                !StringUtils.hasText(request.ville()) &&
                !StringUtils.hasText(request.codePostal()) &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
    }

    /**
     * Détermine si c'est une recherche exacte par email
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
        return isOnlyEmailSearch(request);
    }

    /**
     * Vérifie si seul l'email est utilisé comme critère
     */
    private boolean isOnlyEmailSearch(PatientSearchRequest request) {
        return !request.isNomCompletSearch() &&
                !request.isNomPrenomSearch() &&
                (request.numeroSecu() == null || request.numeroSecu().trim().isEmpty()) &&
                (request.telephone() == null || request.telephone().trim().isEmpty()) &&
                (request.ville() == null || request.ville().trim().isEmpty()) &&
                request.codePostal() == null &&
                request.dateNaissance() == null &&
                request.sexe() == null &&
                request.statut() == null;
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
        String nomComplet = String.format("%s %s",
                patient.getNom() != null ? patient.getNom() : "",
                patient.getPrenom() != null ? patient.getPrenom() : "").trim();

        Integer age = null;
        if (patient.getDateNaissance() != null) {
            age = Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
        }

        return PatientSummaryResponse.builder()
                .id(patient.getId().toString())
                .nomComplet(nomComplet)
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(age)
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    // ===== MÉTHODES STATISTIQUES (inchangées) =====

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
import com.lims.patient.enums.DeliveryMethod;
import com.lims.patient.enums.NotificationPreference;
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
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service principal pour la gestion des patients
 * Architecture séparée : CRUD dans PatientService, recherches dans PatientSearchService
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PatientService {

    private final PatientRepository patientRepository;
    private final PatientSearchService patientSearchService; // Délégation pour les recherches

    // ====================================================================
    // MÉTHODES CRUD PRINCIPALES
    // ====================================================================

    /**
     * Crée un nouveau patient avec structure centralisée
     */
    public PatientResponse createPatient(CreatePatientRequest request, String createdBy) {
        log.debug("Création d'un nouveau patient: {} {} avec {} spécificités par {}",
                request.personalInfo().prenom(),
                request.personalInfo().nom(),
                request.specificities() != null && request.specificities().specificityIds() != null
                        ? request.specificities().specificityIds().size() : 0,
                createdBy);

        // 1. Validation des données (existante)
        validateCreateRequest(request);

        // 2. Vérification des doublons (existante)
        checkForDuplicates(request);

        // 3. Construction de l'entité Patient avec createdBy
        Patient patient = buildPatientFromRequest(request, createdBy);

        // 4. AJOUT SPÉCIFICITÉS - UNIQUEMENT LES IDs
        if (request.specificities() != null && request.specificities().specificityIds() != null) {
            patient.setSpecificityIds(new ArrayList<>(request.specificities().specificityIds()));
            log.debug("Spécificités ajoutées au patient: {}", request.specificities().specificityIds());
        }

        // 5. AJOUT COMMENTAIRE PATIENT - DIRECTEMENT SUR PATIENT
        if (StringUtils.hasText(request.commentairePatient())) {
            patient.setCommentairePatient(request.commentairePatient());
            log.debug("Commentaire patient ajouté");
        }

        // 6. Ajout des assurances (existant)
        if (request.insurances() != null) {
            for (InsuranceRequest insuranceRequest : request.insurances()) {
                PatientAssurance assurance = buildAssuranceFromRequest(insuranceRequest);
                patient.addAssurance(assurance);
            }
        }

        // 7. Sauvegarde
        Patient savedPatient;
        try {
            savedPatient = patientRepository.saveAndFlush(patient); // ✅ Force l'SQL immédiatement
            log.info("Patient sauvegardé en BDD avec succès: {} (ID: {})",
                    savedPatient.getNomComplet(), savedPatient.getId());
        } catch (Exception e) {
            log.error("ERREUR SQL lors de la sauvegarde du patient: {}", e.getMessage());
            throw e; // L'erreur apparaîtra ici, pas plus tard
        }

        log.info("Patient créé avec succès: {} (ID: {}), {} spécificité(s), commentaire: {}",
                savedPatient.getNomComplet(),
                savedPatient.getId(),
                savedPatient.getSpecificitiesCount(),
                savedPatient.getCommentairePatient() != null ? "oui" : "non");

        return mapToPatientResponse(savedPatient);
    }

    /**
     * Récupère un patient par son ID
     */
    @Transactional(readOnly = true)
    public PatientResponse getPatient(UUID id) {
        log.debug("Récupération du patient: {}", id);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        return mapToPatientResponse(patient);
    }

    /**
     * Met à jour un patient existant
     */
    public PatientResponse updatePatient(UUID id, UpdatePatientRequest request) {
        log.info("Mise à jour du patient: {}", id);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        // Mettre à jour les champs modifiables
        updatePatientFields(patient, request);

        Patient savedPatient = patientRepository.save(patient);

        log.info("Patient mis à jour: {} (ID: {})", savedPatient.getNomComplet(), id);

        return mapToPatientResponse(savedPatient);
    }

    /**
     * Suppression logique d'un patient
     */
    public void deletePatient(UUID id, String deleteReason) {
        log.info("Suppression logique du patient: {} - Raison: {}", id, deleteReason);

        Patient patient = patientRepository.findByIdAndDateSuppressionIsNull(id)
                .orElseThrow(() -> new PatientNotFoundException("Patient non trouvé: " + id));

        patient.setDateSuppression(LocalDateTime.now());
        patient.setStatut(PatientStatus.INACTIF);

        patientRepository.save(patient);

        log.info("Patient supprimé logiquement: {}", id);
    }

    // ====================================================================
    // MÉTHODES DE RECHERCHE - DÉLÉGATION À PatientSearchService
    // ====================================================================

    /**
     * Recherche multicritères - DÉLÉGUÉ au PatientSearchService
     */
    @Transactional(readOnly = true)
    public PatientSearchResponse searchPatients(PatientSearchRequest request) {
        log.debug("Délégation de la recherche au PatientSearchService");
        return patientSearchService.searchPatients(request);
    }

    /**
     * Recherche rapide par nom complet - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> quickSearchByNomComplet(String nomComplet) {
        return patientSearchService.quickSearchByNomComplet(nomComplet);
    }

    /**
     * Recherche par nom et prénom - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> searchByNomPrenom(String nom, String prenom) {
        return patientSearchService.searchByNomPrenom(nom, prenom);
    }

    /**
     * Recherche par nom et prénom - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> searchByPhone(String phone) {
        return patientSearchService.searchByPhone(phone);
    }

    /**
     * Suggestions d'autocomplétion - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<String> suggestNomComplet(String input) {
        return patientSearchService.suggestNomComplet(input);
    }

    /**
     * Recherche rapide générale - DÉLÉGUÉ
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> quickSearch(String query, int limit) {
        return patientSearchService.quickSearch(query, limit);
    }

    // ====================================================================
    // MÉTHODES DE RECHERCHE SPÉCIFIQUES (restent dans PatientService)
    // ====================================================================

    /**
     * Recherche par email - unique et critique pour l'authentification
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByEmail(String email) {
        log.debug("Recherche par email: {}", email);

        if (!StringUtils.hasText(email)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByEmailAndDateSuppressionIsNull(email.toLowerCase().trim());

        return patient.map(this::mapToPatientResponse);
    }

    /**
     * Recherche par téléphone - unique et critique
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByTelephone(String telephone) {
        log.debug("Recherche par téléphone: {}", telephone);

        if (!StringUtils.hasText(telephone)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByTelephoneAndDateSuppressionIsNull(telephone.trim());

        return patient.map(this::mapToPatientResponse);
    }

    /**
     * Recherche par numéro de sécurité sociale - unique et critique
     */
    @Transactional(readOnly = true)
    public Optional<PatientResponse> findByNumeroSecu(String numeroSecu) {
        log.debug("Recherche par numéro de sécurité sociale");

        if (!StringUtils.hasText(numeroSecu)) {
            return Optional.empty();
        }

        Optional<Patient> patient = patientRepository.findByNumeroSecuAndDateSuppressionIsNull(numeroSecu.trim());

        return patient.map(this::mapToPatientResponse);
    }

    // ====================================================================
    // MÉTHODES UTILITAIRES ET LISTES
    // ====================================================================

    /**
     * Liste des patients actifs avec pagination
     */
    @Transactional(readOnly = true)
    public List<PatientSummaryResponse> getActivePatients(int page, int size) {
        log.debug("Récupération des patients actifs - page: {}, size: {}", page, size);

        Pageable pageable = PageRequest.of(page, size, Sort.by("nom", "prenom"));
        Page<Patient> patients = patientRepository.findByStatutAndDateSuppressionIsNull(
                PatientStatus.ACTIF, pageable);

        return patients.stream()
                .map(this::mapToSummaryResponse)
                .collect(Collectors.toList());
    }

    /**
     * Compte le nombre de patients actifs
     */
    @Transactional(readOnly = true)
    public long countActivePatients() {
        return patientRepository.countByStatutAndDateSuppressionIsNull(PatientStatus.ACTIF);
    }

    /**
     * Vérifie si un patient existe par email
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return false;
        }
        return patientRepository.existsByEmailAndDateSuppressionIsNull(email.toLowerCase().trim());
    }

    /**
     * Vérifie si un patient existe par téléphone
     */
    @Transactional(readOnly = true)
    public boolean existsByTelephone(String telephone) {
        if (!StringUtils.hasText(telephone)) {
            return false;
        }
        return patientRepository.existsByTelephoneAndDateSuppressionIsNull(telephone.trim());
    }

    /**
     * Vérifie si un patient existe par numéro de sécurité sociale
     */
    @Transactional(readOnly = true)
    public boolean existsByNumeroSecu(String numeroSecu) {
        if (!StringUtils.hasText(numeroSecu)) {
            return false;
        }
        return patientRepository.existsByNumeroSecuAndDateSuppressionIsNull(numeroSecu.trim());
    }

    // ====================================================================
    // MÉTHODES PRIVÉES DE SUPPORT
    // ====================================================================

    private void validateCreateRequest(CreatePatientRequest request) {
        if (request.personalInfo() == null) {
            throw new InvalidPatientDataException("Les informations personnelles sont obligatoires");
        }

        if (request.contactInfo() == null) {
            throw new InvalidPatientDataException("Les informations de contact sont obligatoires");
        }

        if (request.consent() == null) {
            throw new InvalidPatientDataException("Les consentements sont obligatoires");
        }

        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        // Validation des informations personnelles obligatoires
        if (!StringUtils.hasText(personalInfo.nom()) || !StringUtils.hasText(personalInfo.prenom())) {
            throw new InvalidPatientDataException("Le nom et le prénom sont obligatoires");
        }

        if (!StringUtils.hasText(personalInfo.numeroSecu())) {
            throw new InvalidPatientDataException("Le numéro de sécurité sociale est obligatoire");
        }

        if (personalInfo.dateNaissance() == null) {
            throw new InvalidPatientDataException("La date de naissance est obligatoire");
        }

        if (personalInfo.sexe() == null) {
            throw new InvalidPatientDataException("Le sexe est obligatoire");
        }

        // Validation des informations de contact obligatoires
        if (!StringUtils.hasText(contactInfo.email())) {
            throw new InvalidPatientDataException("L'email est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.telephone())) {
            throw new InvalidPatientDataException("Le téléphone est obligatoire");
        }

        if (!StringUtils.hasText(contactInfo.adresseLigne1()) ||
                !StringUtils.hasText(contactInfo.codePostal()) ||
                !StringUtils.hasText(contactInfo.ville())) {
            throw new InvalidPatientDataException("L'adresse complète est obligatoire");
        }

        // Validation des consentements obligatoires
        if (consent.createAccount() == null || !consent.createAccount()) {
            throw new InvalidPatientDataException("Le consentement de création de compte est obligatoire");
        }
    }

    private void checkForDuplicates(CreatePatientRequest request) {
        // Vérification par email
        if (existsByEmail(request.contactInfo().email())) {
            throw new DuplicatePatientException("Un patient avec cet email existe déjà");
        }

        // Vérification par téléphone
        if (existsByTelephone(request.contactInfo().telephone())) {
            throw new DuplicatePatientException("Un patient avec ce téléphone existe déjà");
        }

        // Vérification par numéro de sécurité sociale
        if (existsByNumeroSecu(request.personalInfo().numeroSecu())) {
            throw new DuplicatePatientException("Un patient avec ce numéro de sécurité sociale existe déjà");
        }
    }

    private Patient buildPatientFromRequest(CreatePatientRequest request, String createdBy) {
        PersonalInfoRequest personalInfo = request.personalInfo();
        ContactInfoRequest contactInfo = request.contactInfo();
        ConsentRequest consent = request.consent();

        Patient patient = new Patient();
        // L'ID sera généré automatiquement par @GeneratedValue(strategy = GenerationType.UUID)

        // === INFORMATIONS PERSONNELLES ===
        patient.setNom(personalInfo.nom().toUpperCase().trim());
        patient.setPrenom(capitalizeFirstLetter(personalInfo.prenom().trim()));
        patient.setNomJeuneFille(personalInfo.nomJeuneFille());
        patient.setDateNaissance(personalInfo.dateNaissance());
        patient.setLieuNaissance(personalInfo.lieuNaissance());
        patient.setSexe(personalInfo.sexe());
        patient.setNumeroSecu(personalInfo.numeroSecu());
        patient.setMedecinTraitant(personalInfo.medecinTraitant());
        patient.setAllergiesConnues(personalInfo.allergiesConnues());
        patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());

        // === INFORMATIONS DE CONTACT CENTRALISÉES ===
        patient.setEmail(contactInfo.email().toLowerCase().trim());
        patient.setTelephone(contactInfo.telephone());
        patient.setAdresseLigne1(contactInfo.adresseLigne1());
        patient.setAdresseLigne2(contactInfo.adresseLigne2());
        patient.setCodePostal(contactInfo.codePostal());
        patient.setVille(contactInfo.ville());
        patient.setDepartement(contactInfo.departement());
        patient.setRegion(contactInfo.region());
        patient.setPays(contactInfo.pays() != null ? contactInfo.pays() : "France");
        patient.setLatitude(contactInfo.latitude());
        patient.setLongitude(contactInfo.longitude());

        // === PRÉFÉRENCES DE COMMUNICATION ===
        patient.setMethodeLivraisonPreferee(DeliveryMethod.EMAIL);
        patient.setPreferenceNotification(NotificationPreference.TOUS);
        patient.setLanguePreferee(contactInfo.languePreferee() != null ? contactInfo.languePreferee() : "fr-FR");
        patient.setNotificationsResultats(contactInfo.notificationsResultats() != null ? contactInfo.notificationsResultats() : true);
        patient.setNotificationsRdv(contactInfo.notificationsRdv() != null ? contactInfo.notificationsRdv() : true);
        patient.setNotificationsRappels(contactInfo.notificationsRappels() != null ? contactInfo.notificationsRappels() : true);

        // === CONSENTEMENTS RGPD ===
        patient.setConsentementCreationCompte(consent.createAccount());
        patient.setConsentementSms(consent.sms());
        patient.setConsentementEmail(consent.email());
        patient.setDateConsentement(LocalDateTime.now());

        // === MÉTADONNÉES ===
        patient.setStatut(PatientStatus.ACTIF);
        patient.setDateCreation(LocalDateTime.now());
        patient.setCreepar(request.createdBy() != null ? request.createdBy() : "SYSTEM");

        patient.setCreepar(createdBy);

        return patient;
    }

    private PatientAssurance buildAssuranceFromRequest(InsuranceRequest request) {
        PatientAssurance assurance = new PatientAssurance();
        // L'ID sera généré automatiquement si l'entité a @GeneratedValue
        assurance.setTypeAssurance(request.typeAssurance());
        assurance.setNomOrganisme(request.nomOrganisme());
        assurance.setNumeroAdherent(request.numeroAdherent());
        assurance.setDateDebut(request.dateDebut());
        assurance.setDateFin(request.dateFin());
        assurance.setTiersPayantAutorise(request.tiersPayantAutorise());
        assurance.setPourcentagePriseCharge(request.pourcentagePriseCharge());
        assurance.setReferenceDocument(request.referenceDocument());
        assurance.setEstActive(true);
        return assurance;
    }

    private void updatePatientFields(Patient patient, UpdatePatientRequest request) {
        // Mise à jour des informations personnelles
        if (request.personalInfo() != null) {
            PersonalInfoUpdateRequest personalInfo = request.personalInfo(); // ← Correction du type
            if (StringUtils.hasText(personalInfo.nom())) {
                patient.setNom(personalInfo.nom().toUpperCase().trim());
            }
            if (StringUtils.hasText(personalInfo.prenom())) {
                patient.setPrenom(capitalizeFirstLetter(personalInfo.prenom().trim()));
            }
            if (personalInfo.dateNaissance() != null) {
                patient.setDateNaissance(personalInfo.dateNaissance());
            }
            if (personalInfo.sexe() != null) {
                patient.setSexe(personalInfo.sexe());
            }
            if (StringUtils.hasText(personalInfo.nomJeuneFille())) {
                patient.setNomJeuneFille(personalInfo.nomJeuneFille());
            }
            if (StringUtils.hasText(personalInfo.lieuNaissance())) {
                patient.setLieuNaissance(personalInfo.lieuNaissance());
            }
            if (StringUtils.hasText(personalInfo.medecinTraitant())) {
                patient.setMedecinTraitant(personalInfo.medecinTraitant());
            }
            if (personalInfo.allergiesConnues() != null) {
                patient.setAllergiesConnues(personalInfo.allergiesConnues());
            }
            if (personalInfo.antecedentsMedicaux() != null) {
                patient.setAntecedentsMedicaux(personalInfo.antecedentsMedicaux());
            }
        }

        // Mise à jour des informations de contact
        if (request.contactInfo() != null) {
            ContactInfoUpdateRequest contactInfo = request.contactInfo(); // ← Probablement aussi à corriger
            if (StringUtils.hasText(contactInfo.email())) {
                patient.setEmail(contactInfo.email().toLowerCase().trim());
            }
            if (StringUtils.hasText(contactInfo.telephone())) {
                patient.setTelephone(contactInfo.telephone());
            }
            if (StringUtils.hasText(contactInfo.adresseLigne1())) {
                patient.setAdresseLigne1(contactInfo.adresseLigne1());
            }
            if (contactInfo.adresseLigne2() != null) {
                patient.setAdresseLigne2(contactInfo.adresseLigne2());
            }
            if (StringUtils.hasText(contactInfo.codePostal())) {
                patient.setCodePostal(contactInfo.codePostal());
            }
            if (StringUtils.hasText(contactInfo.ville())) {
                patient.setVille(contactInfo.ville());
            }
            if (contactInfo.departement() != null) {
                patient.setDepartement(contactInfo.departement());
            }
            if (contactInfo.region() != null) {
                patient.setRegion(contactInfo.region());
            }
            if (contactInfo.pays() != null) {
                patient.setPays(contactInfo.pays());
            }
            if (contactInfo.preferenceNotification() != null) {
                patient.setPreferenceNotification(contactInfo.preferenceNotification());
            }
            if (contactInfo.languePreferee() != null) {
                patient.setLanguePreferee(contactInfo.languePreferee());
            }
        }

        patient.setDateModification(LocalDateTime.now());
        patient.setModifiePar("SYSTEM"); // À adapter selon le contexte d'authentification
    }

    private String capitalizeFirstLetter(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }

    /**
     * Mapping complet vers PatientResponse
     */
    private PatientResponse mapToPatientResponse(Patient patient) {
        // Construction des informations personnelles
        PersonalInfoResponse personalInfo = PersonalInfoResponse.builder()
                .nom(patient.getNom())
                .prenom(patient.getPrenom())
                .nomJeuneFille(patient.getNomJeuneFille())
                .dateNaissance(patient.getDateNaissance())
                .lieuNaissance(patient.getLieuNaissance())
                .sexe(patient.getSexe())
                .numeroSecuMasque(maskNumeroSecu(patient.getNumeroSecu()))
                .age(patient.getAge())
                .medecinTraitant(patient.getMedecinTraitant())
                .allergiesConnues(patient.getAllergiesConnues())
                .antecedentsMedicaux(patient.getAntecedentsMedicaux())
                .build();

        // Construction des informations de contact
        ContactInfoResponse contactInfo = ContactInfoResponse.builder()
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
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

        // Construction des consentements
        ConsentResponse consent = ConsentResponse.builder()
                .createAccount(patient.getConsentementCreationCompte())
                .sms(patient.getConsentementSms())
                .email(patient.getConsentementEmail())
                .dateConsentement(patient.getDateConsentement())
                .build();

        // Construction des métadonnées
        MetadataResponse metadata = MetadataResponse.builder()
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .dateModification(patient.getDateModification())
                .creePar(patient.getCreePar())
                .modifiePar(patient.getModifiePar())
                .actif(patient.getStatut() == PatientStatus.ACTIF)
                .build();

        return PatientResponse.builder()
                .id(patient.getId().toString()) // Convertir UUID en String pour le DTO
                .personalInfo(personalInfo)
                .contactInfo(contactInfo)
                .consent(consent)
                .build();
    }

    /**
     * Mapping simplifié vers PatientSummaryResponse
     */
    private PatientSummaryResponse mapToSummaryResponse(Patient patient) {
        String nomComplet = String.format("%s %s",
                patient.getNom() != null ? patient.getNom() : "",
                patient.getPrenom() != null ? patient.getPrenom() : "").trim();

        Integer age = null;
        if (patient.getDateNaissance() != null) {
            age = Period.between(patient.getDateNaissance(), LocalDate.now()).getYears();
        }

        return PatientSummaryResponse.builder()
                .id(patient.getId().toString()) // Convertir UUID en String pour le DTO
                .nomComplet(nomComplet)
                .email(patient.getEmail())
                .telephone(patient.getTelephone())
                .dateNaissance(patient.getDateNaissance())
                .age(age)
                .sexe(patient.getSexe())
                .ville(patient.getVille())
                .statut(patient.getStatut())
                .dateCreation(patient.getDateCreation())
                .build();
    }

    private String maskNumeroSecu(String numeroSecu) {
        if (numeroSecu == null || numeroSecu.length() < 8) {
            return "****";
        }
        return numeroSecu.substring(0, 4) + "***" + numeroSecu.substring(numeroSecu.length() - 2);
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
        if (consent.createAccount() == null || !consent.createAccount()) {
            throw new ConsentValidationException(
                    "CREATION_COMPTE",
                    "Le consentement pour la création de compte est obligatoire");
        }

        // Validation cohérence consentements
        if (consent.email() != null && consent.email()) {
            // Si consentement email, vérifier que l'email est valide
            if (!StringUtils.hasText(request.contactInfo().email())) {
                throw new ConsentValidationException(
                        "EMAIL",
                        "Impossible de donner le consentement email sans adresse email valide");
            }
        }

        if (consent.sms() != null && consent.sms()) {
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
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Spécifications JPA complètes pour les requêtes de recherche de patients
 * Version adaptée avec support du nomComplet
 */
@Slf4j
public class PatientSpecifications {

    // ===== SPÉCIFICATIONS DE BASE =====

    /**
     * Specification de base : patient non supprimé
     */
    public static Specification<Patient> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.isNull(root.get("dateSuppression"));
    }

    // ===== SPÉCIFICATIONS POUR NOM COMPLET =====

    /**
     * Recherche par nom complet - version simple
     */
    public static Specification<Patient> nomCompletContains(String nomComplet) {
        return (root, query, criteriaBuilder) -> {
            if (!StringUtils.hasText(nomComplet)) {
                return criteriaBuilder.conjunction();
            }

            String searchValue = "%" + nomComplet.toLowerCase() + "%";

            // Créer une expression concaténée : nom + " " + prenom
            Expression<String> nomCompletExpression = criteriaBuilder.concat(
                    criteriaBuilder.lower(root.get("nom")),
                    criteriaBuilder.concat(" ", criteriaBuilder.lower(root.get("prenom")))
            );

            // Aussi créer l'expression inverse : prenom + " " + nom
            Expression<String> prenomNomExpression = criteriaBuilder.concat(
                    criteriaBuilder.lower(root.get("prenom")),
                    criteriaBuilder.concat(" ", criteriaBuilder.lower(root.get("nom")))
            );

            // Chercher dans les deux sens
            Predicate nomPrenomMatch = criteriaBuilder.like(nomCompletExpression, searchValue);
            Predicate prenomNomMatch = criteriaBuilder.like(prenomNomExpression, searchValue);

            // Aussi chercher dans nom seul et prénom seul
            Predicate nomSeulMatch = criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("nom")), searchValue);
            Predicate prenomSeulMatch = criteriaBuilder.like(
                    criteriaBuilder.lower(root.get("prenom")), searchValue);

            return criteriaBuilder.or(nomPrenomMatch, prenomNomMatch, nomSeulMatch, prenomSeulMatch);
        };
    }

    /**
     * Recherche avancée par nom complet avec mots-clés multiples
     */
    public static Specification<Patient> nomCompletAdvanced(String nomComplet) {
        return (root, query, criteriaBuilder) -> {
            if (!StringUtils.hasText(nomComplet)) {
                return criteriaBuilder.conjunction();
            }

            String[] keywords = nomComplet.trim().toLowerCase().split("\\s+");

            if (keywords.length == 1) {
                // Un seul mot : recherche simple
                return nomCompletContains(nomComplet).toPredicate(root, query, criteriaBuilder);
            }

            // Plusieurs mots : chaque mot doit être trouvé dans nom OU prénom
            List<Predicate> keywordPredicates = new ArrayList<>();

            for (String keyword : keywords) {
                String searchValue = "%" + keyword + "%";

                Predicate nomMatch = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("nom")), searchValue);
                Predicate prenomMatch = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("prenom")), searchValue);

                keywordPredicates.add(criteriaBuilder.or(nomMatch, prenomMatch));
            }

            // Tous les mots-clés doivent être trouvés (AND)
            return criteriaBuilder.and(keywordPredicates.toArray(new Predicate[0]));
        };
    }

    // ===== SPÉCIFICATIONS INDIVIDUELLES =====

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
     * Recherche par téléphone (recherche partielle avec nettoyage des caractères)
     */
    public static Specification<Patient> hasTelephone(String telephone) {
        return (root, query, criteriaBuilder) -> {
            if (telephone == null || telephone.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            // Nettoyer le numéro de recherche
            String cleanSearchPhone = telephone.replaceAll("[^0-9+]", "");
            String searchTerm = "%" + cleanSearchPhone + "%";

            // Recherche dans le téléphone nettoyé
            return criteriaBuilder.like(
                    criteriaBuilder.function("REGEXP_REPLACE", String.class,
                            root.get("telephone"),
                            criteriaBuilder.literal("[^0-9+]"),
                            criteriaBuilder.literal("")),
                    searchTerm
            );
        };
    }

    /**
     * Recherche par ville (recherche partielle, insensible à la casse)
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
     * Recherche par numéro de sécurité sociale (égalité exacte)
     */
    public static Specification<Patient> hasNumeroSecu(String numeroSecu) {
        return (root, query, criteriaBuilder) -> {
            if (numeroSecu == null || numeroSecu.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(root.get("numeroSecu"), numeroSecu.trim());
        };
    }

    // ===== SPÉCIFICATIONS COMPOSÉES =====

    /**
     * Patients actifs (non supprimés + statut actif)
     */
    public static Specification<Patient> active() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.and(
                        criteriaBuilder.isNull(root.get("dateSuppression")),
                        criteriaBuilder.equal(root.get("statut"), PatientStatus.ACTIF)
                );
    }

    /**
     * Recherche générale multi-critères (version legacy pour compatibilité)
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

    // ===== SPÉCIFICATIONS UTILITAIRES =====

    /**
     * Recherche par tranche d'âge
     */
    public static Specification<Patient> ageEntre(int ageMin, int ageMax) {
        return (root, query, criteriaBuilder) -> {
            LocalDate now = LocalDate.now();
            LocalDate dateMaxNaissance = now.minusYears(ageMin);
            LocalDate dateMinNaissance = now.minusYears(ageMax + 1);

            return criteriaBuilder.between(
                    root.get("dateNaissance"),
                    dateMinNaissance,
                    dateMaxNaissance
            );
        };
    }

    /**
     * Patients créés récemment (derniers X jours)
     */
    public static Specification<Patient> creesDepuis(int jours) {
        return (root, query, criteriaBuilder) -> {
            LocalDate dateLimit = LocalDate.now().minusDays(jours);
            return criteriaBuilder.greaterThanOrEqualTo(
                    criteriaBuilder.function("DATE", LocalDate.class, root.get("dateCreation")),
                    dateLimit
            );
        };
    }

    /**
     * Recherche par département (basée sur le code postal)
     */
    public static Specification<Patient> dansLeDepartement(String codeDepartement) {
        return (root, query, criteriaBuilder) -> {
            if (codeDepartement == null || codeDepartement.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            String pattern = codeDepartement.trim() + "%";
            return criteriaBuilder.like(root.get("codePostal"), pattern);
        };
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

# lims-ref-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.lims</groupId>
        <artifactId>lims-system</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>lims-ref-service</artifactId>
    <packaging>jar</packaging>

    <name>LIMS Referential Service</name>
    <description>Service de gestion des données de référence pour le système LIMS</description>

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
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- PostgreSQL Driver -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- JWT Support - AJOUT NÉCESSAIRE -->
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

        <!-- MapStruct -->
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>${mapstruct.version}</version>
        </dependency>

        <!-- OpenAPI Documentation -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>2.2.0</version>
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
            <!-- Spring Boot Plugin -->
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
                <version>${maven.compiler.plugin.version}</version>
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
                            <version>${lombok.version}</version>
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

# lims-ref-service/src/main/java/com/lims/referential/config/AdminJwtAuthenticationConverter.java

```java
package com.lims.referential.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.List;

/**
 * Convertisseur d'authentification JWT pour les administrateurs.
 * Attribue automatiquement le role ADMIN aux utilisateurs valides.
 */
public class AdminJwtAuthenticationConverter extends JwtAuthenticationConverter {

    public AdminJwtAuthenticationConverter() {
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Pour le service référentiel, tous les utilisateurs valides sont admins
        return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/config/AdminJwtDecoder.java

```java
package com.lims.referential.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Décodeur JWT simple pour valider uniquement les tokens admin du realm lims-admin.
 * Ce service de référentiel n'accepte que les administrateurs.
 */
@Slf4j
public class AdminJwtDecoder implements JwtDecoder {

    private final String jwtSecret;

    public AdminJwtDecoder(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        try {
            log.debug("Decoding JWT token for referential service");

            // Créer la clé secrète pour HMAC SHA512
            SecretKeySpec secretKey = new SecretKeySpec(
                    jwtSecret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA512"
            );

            // Décoder avec JJWT
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("JWT decoded successfully for subject: {}", claims.getSubject());

            // VALIDATION STRICTE : Vérifier que c'est un token admin
            String realm = (String) claims.get("realm");
            String userType = (String) claims.get("user_type");

            if (!"lims-admin".equals(realm)) {
                log.warn("Invalid realm for referential service: {}. Expected: lims-admin", realm);
                throw new JwtException("Invalid realm. Referential service only accepts admin tokens.");
            }

            if (!"ADMIN".equals(userType)) {
                log.warn("Invalid user type for referential service: {}. Expected: ADMIN", userType);
                throw new JwtException("Invalid user type. Referential service only accepts admin users.");
            }

            // Convertir en Spring Security Jwt
            return createSpringJwt(token, claims);

        } catch (JwtException e) {
            // Re-lancer les JwtException
            throw e;
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

        Instant issuedAt = claims.getIssuedAt() != null ?
                claims.getIssuedAt().toInstant() : Instant.now();
        Instant expiresAt = claims.getExpiration() != null ?
                claims.getExpiration().toInstant() : Instant.now().plusSeconds(3600);

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

# lims-ref-service/src/main/java/com/lims/referential/config/CacheConfig.java

```java
package com.lims.referential.config;

import org.springframework.context.annotation.Configuration;

/**
 * Configuration du cache Redis avec TTL adaptés par type de données
 */
@Configuration
public class CacheConfig {

    public static final String ANALYSES_CACHE = "analyses";
    public static final String MEDECINS_CACHE = "medecins";
    public static final String LABORATOIRES_CACHE = "laboratoires";
    public static final String MEDICAMENTS_CACHE = "medicaments";
    public static final String MUTUELLES_CACHE = "mutuelles";
    public static final String GEOGRAPHIQUE_CACHE = "geographique";
    public static final String PATIENT_SPECIFICITIES_CACHE = "patient-specificities";

    // Cache TTL en secondes
    public static final int ANALYSES_TTL = 3600; // 1 heure
    public static final int MEDECINS_TTL = 7200; // 2 heures
    public static final int LABORATOIRES_TTL = 1800; // 30 minutes
    public static final int MEDICAMENTS_TTL = 3600; // 1 heure
    public static final int MUTUELLES_TTL = 7200; // 2 heures
    public static final int GEOGRAPHIQUE_TTL = 86400; // 24 heures (données stables)
    public static final int PATIENT_SPECIFICITIES_TTL = 1800; // 30 minutes
}

```

# lims-ref-service/src/main/java/com/lims/referential/config/DatabaseConfig.java

```java
package com.lims.referential.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Configuration de la base de données et de l'audit JPA pour le service référentiel.
 */
@Configuration
@EnableJpaRepositories(basePackages = "com.lims.referential.repository")
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class DatabaseConfig {

    /**
     * Auditor pour JPA Auditing - utilise l'utilisateur admin connecté
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

# lims-ref-service/src/main/java/com/lims/referential/config/OpenApiConfig.java

```java
package com.lims.referential.config;

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
 * Configuration OpenAPI pour le service référentiel LIMS.
 * Ce service gère les données de référence du système.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI referentialServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LIMS Referential Service API")
                        .description("API de gestion des données de référence pour le système LIMS de laboratoire de biologie médicale. Ce service fournit les nomenclatures, tarifs, analyses disponibles et autres données de référence nécessaires au fonctionnement du LIMS.")
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
                                .url("http://localhost:8093")
                                .description("Serveur de développement"),
                        new Server()
                                .url("https://api.lims.com/referential")
                                .description("Serveur de production")))
                .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("Bearer Authentication",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Token JWT admin obtenu via le service d'authentification (realm: lims-admin)")));
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/config/SecurityConfig.java

```java
package com.lims.referential.config;

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
 * Configuration de sécurité pour le service référentiel LIMS.
 * Ce service n'accepte que les tokens JWT du realm lims-admin.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Value("${lims.jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .authorizeHttpRequests(auth -> auth
                        // Endpoints publics
                        .requestMatchers(
                                "/actuator/**",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        // Tous les autres endpoints nécessitent une authentification admin
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
        return new AdminJwtDecoder(jwtSecret);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new AdminJwtAuthenticationConverter();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Origines autorisées
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Méthodes HTTP autorisées
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"
        ));

        // Headers autorisés
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Headers exposés pour les réponses
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

# lims-ref-service/src/main/java/com/lims/referential/config/ValidationConfig.java

```java
package com.lims.referential.config;

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

# lims-ref-service/src/main/java/com/lims/referential/controller/AnalyseController.java

```java
// AnalyseController.java
package com.lims.referential.controller;

import com.lims.referential.service.AnalyseService;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.dto.response.PagedResponseDTO;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des analyses biologiques
 */
@RestController
@RequestMapping("/api/v1/analyses")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Analyses Biologiques", description = "API de gestion des analyses biologiques avec codes NABM")
public class AnalyseController {

    private final AnalyseService analyseService;

    @Operation(summary = "Lister toutes les analyses", description = "Récupère la liste paginée de toutes les analyses biologiques actives")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Liste récupérée avec succès"), @ApiResponse(responseCode = "400", description = "Paramètres de pagination invalides")})
    @GetMapping
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> getAllAnalyses(@Parameter(description = "Numéro de page (commence à 0)") @RequestParam(defaultValue = "0") int page, @Parameter(description = "Taille de la page (max 100)") @RequestParam(defaultValue = "20") int size, @Parameter(description = "Critère de tri (ex: libelle,asc)") @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses - page: {}, size: {}, sort: {}", page, size, sort);

        // Validation des paramètres
        if (size > 100) size = 100;
        if (page < 0) page = 0;

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.findAll(pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Obtenir une analyse par ID", description = "Récupère les détails d'une analyse spécifique par son identifiant")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse trouvée"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @GetMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> getAnalyseById(@Parameter(description = "Identifiant unique de l'analyse") @PathVariable UUID id) {

        log.debug("GET /api/v1/analyses/{}", id);
        AnalyseResponseDTO analyse = analyseService.findById(id);
        return ResponseEntity.ok(analyse);
    }

    @Operation(summary = "Rechercher des analyses", description = "Recherche textuelle dans les analyses par libellé, code NABM ou description")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Recherche effectuée avec succès"), @ApiResponse(responseCode = "400", description = "Terme de recherche invalide")})
    @GetMapping("/search")
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> searchAnalyses(@Parameter(description = "Terme de recherche") @RequestParam String q, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size, @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses/search - q: '{}', page: {}, size: {}", q, page, size);

        if (q == null || q.trim().length() < 2) {
            throw new IllegalArgumentException("Le terme de recherche doit contenir au moins 2 caractères");
        }

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.search(q.trim(), pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Auto-complétion des analyses", description = "Suggestions d'analyses pour l'auto-complétion")
    @GetMapping("/suggest")
    public ResponseEntity<List<AnalyseResponseDTO>> suggestAnalyses(@Parameter(description = "Préfixe pour l'auto-complétion") @RequestParam String q) {

        log.debug("GET /api/v1/analyses/suggest - q: '{}'", q);

        if (q == null || q.trim().length() < 1) {
            return ResponseEntity.ok(List.of());
        }

        List<AnalyseResponseDTO> suggestions = analyseService.suggest(q.trim());
        return ResponseEntity.ok(suggestions);
    }

    @Operation(summary = "Filtrer les analyses", description = "Filtrage multi-critères des analyses")
    @GetMapping("/filter")
    public ResponseEntity<PagedResponseDTO<AnalyseResponseDTO>> filterAnalyses(@Parameter(description = "Catégorie d'analyse") @RequestParam(required = false) CategorieAnalyse categorie, @Parameter(description = "Sous-catégorie d'analyse") @RequestParam(required = false) String sousCategorie, @Parameter(description = "Statut actif/inactif") @RequestParam(required = false) Boolean actif, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size, @RequestParam(defaultValue = "libelle,asc") String sort) {

        log.debug("GET /api/v1/analyses/filter - catégorie: {}, sous-catégorie: {}, actif: {}", categorie, sousCategorie, actif);

        // Parse du critère de tri
        String[] sortParams = sort.split(",");
        String sortField = sortParams[0];
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1]) ? Sort.Direction.DESC : Sort.Direction.ASC;

        Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortField));
        PagedResponseDTO<AnalyseResponseDTO> result = analyseService.findWithFilters(categorie, sousCategorie, actif, pageable);

        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Créer une nouvelle analyse", description = "Crée une nouvelle analyse biologique avec validation des données")
    @ApiResponses({@ApiResponse(responseCode = "201", description = "Analyse créée avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "409", description = "Code NABM déjà existant")})
    @PostMapping
    public ResponseEntity<AnalyseResponseDTO> createAnalyse(@Parameter(description = "Données de l'analyse à créer") @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("POST /api/v1/analyses - Création d'une analyse avec code NABM: {}", requestDTO.getCodeNabm());

        AnalyseResponseDTO createdAnalyse = analyseService.create(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdAnalyse);
    }

    @Operation(summary = "Mettre à jour une analyse", description = "Met à jour complètement une analyse existante")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse mise à jour avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée"), @ApiResponse(responseCode = "409", description = "Code NABM déjà existant")})
    @PutMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> updateAnalyse(@Parameter(description = "Identifiant de l'analyse à modifier") @PathVariable UUID id, @Parameter(description = "Nouvelles données de l'analyse") @Valid @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("PUT /api/v1/analyses/{} - Mise à jour de l'analyse", id);

        AnalyseResponseDTO updatedAnalyse = analyseService.update(id, requestDTO);
        return ResponseEntity.ok(updatedAnalyse);
    }

    @Operation(summary = "Mise à jour partielle d'une analyse", description = "Met à jour partiellement une analyse existante")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "Analyse mise à jour avec succès"), @ApiResponse(responseCode = "400", description = "Données invalides"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @PatchMapping("/{id}")
    public ResponseEntity<AnalyseResponseDTO> patchAnalyse(@Parameter(description = "Identifiant de l'analyse à modifier") @PathVariable UUID id, @Parameter(description = "Données partielles de l'analyse") @RequestBody AnalyseRequestDTO requestDTO) {

        log.info("PATCH /api/v1/analyses/{} - Mise à jour partielle de l'analyse", id);

        AnalyseResponseDTO updatedAnalyse = analyseService.update(id, requestDTO);
        return ResponseEntity.ok(updatedAnalyse);
    }

    @Operation(summary = "Supprimer une analyse", description = "Supprime logiquement une analyse (soft delete)")
    @ApiResponses({@ApiResponse(responseCode = "204", description = "Analyse supprimée avec succès"), @ApiResponse(responseCode = "404", description = "Analyse non trouvée")})
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAnalyse(@Parameter(description = "Identifiant de l'analyse à supprimer") @PathVariable UUID id) {

        log.info("DELETE /api/v1/analyses/{} - Suppression de l'analyse", id);

        analyseService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Statistiques des analyses", description = "Récupère les statistiques générales des analyses")
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAnalysesStatistics() {
        log.debug("GET /api/v1/analyses/stats");

        Map<String, Object> statistics = analyseService.getStatistics();
        return ResponseEntity.ok(statistics);
    }

    @Operation(summary = "Export CSV des analyses", description = "Exporte toutes les analyses au format CSV")
    @GetMapping("/export")
    public ResponseEntity<String> exportAnalyses(@Parameter(description = "Format d'export (csv par défaut)") @RequestParam(defaultValue = "csv") String format) {

        log.info("GET /api/v1/analyses/export - format: {}", format);

        if (!"csv".equalsIgnoreCase(format)) {
            throw new IllegalArgumentException("Format non supporté: " + format);
        }

        // TODO: Implémenter l'export CSV
        return ResponseEntity.ok("Export CSV non encore implémenté");
    }

    @Operation(summary = "Import CSV des analyses", description = "Importe des analyses depuis un fichier CSV")
    @PostMapping("/import")
    public ResponseEntity<Map<String, Object>> importAnalyses(@Parameter(description = "Remplacer les analyses existantes") @RequestParam(defaultValue = "false") boolean replaceExisting) {

        log.info("POST /api/v1/analyses/import - replaceExisting: {}", replaceExisting);

        // TODO: Implémenter l'import CSV
        Map<String, Object> result = Map.of("message", "Import CSV non encore implémenté", "imported", 0, "errors", List.of());

        return ResponseEntity.ok(result);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/controller/MedicamentController.java

```java
package com.lims.referential.controller;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.service.MedicamentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des médicaments référentiels.
 * Accessible uniquement aux administrateurs.
 */
@RestController
@RequestMapping("/api/v1/referential/medicaments")
@Tag(name = "Medicaments", description = "Gestion des médicaments référentiels")
@SecurityRequirement(name = "Bearer Authentication")
@RequiredArgsConstructor
@Slf4j
public class MedicamentController {

    private final MedicamentService medicamentService;

    // ============================================
    // ENDPOINTS DE CONSULTATION
    // ============================================

    @GetMapping
    @Operation(summary = "Liste des médicaments avec pagination",
            description = "Récupère la liste paginée de tous les médicaments")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<MedicamentResponse>> getAllMedicaments(
            @PageableDefault(size = 20) Pageable pageable) {

        log.debug("Récupération des médicaments avec pagination: {}", pageable);
        Page<MedicamentResponse> medicaments = medicamentService.findAll(pageable);
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/actifs")
    @Operation(summary = "Liste des médicaments actifs",
            description = "Récupère tous les médicaments actifs (non paginé)")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsActifs() {

        log.debug("Récupération de tous les médicaments actifs");
        List<MedicamentResponse> medicaments = medicamentService.findAllActifs();
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Détails d'un médicament",
            description = "Récupère les détails d'un médicament par son ID")
    @ApiResponse(responseCode = "200", description = "Médicament trouvé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> getMedicamentById(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.debug("Récupération du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.findById(id);
        return ResponseEntity.ok(medicament);
    }

    @GetMapping("/code-cis/{codeCis}")
    @Operation(summary = "Médicament par code CIS",
            description = "Récupère un médicament par son code CIS")
    @ApiResponse(responseCode = "200", description = "Médicament trouvé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> getMedicamentByCodeCis(
            @Parameter(description = "Code CIS du médicament") @PathVariable String codeCis) {

        log.debug("Récupération du médicament avec code CIS: {}", codeCis);
        MedicamentResponse medicament = medicamentService.findByCodeCis(codeCis);
        return ResponseEntity.ok(medicament);
    }

    // ============================================
    // ENDPOINTS DE RECHERCHE
    // ============================================

    @GetMapping("/search")
    @Operation(summary = "Recherche de médicaments",
            description = "Recherche de médicaments par dénomination")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> searchMedicaments(
            @Parameter(description = "Terme de recherche") @RequestParam String q) {

        log.debug("Recherche de médicaments: {}", q);
        List<MedicamentResponse> medicaments = medicamentService.searchByDenomination(q);
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/rembourses")
    @Operation(summary = "Médicaments remboursés",
            description = "Récupère les médicaments remboursés par la Sécurité sociale")
    @ApiResponse(responseCode = "200", description = "Liste des médicaments remboursés")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsRembourses() {

        log.debug("Récupération des médicaments remboursés");
        List<MedicamentResponse> medicaments = medicamentService.findMedicamentsRembourses();
        return ResponseEntity.ok(medicaments);
    }

    @GetMapping("/surveillance")
    @Operation(summary = "Médicaments sous surveillance",
            description = "Récupère les médicaments sous surveillance renforcée")
    @ApiResponse(responseCode = "200", description = "Liste des médicaments sous surveillance")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<MedicamentResponse>> getMedicamentsSurveillance() {

        log.debug("Récupération des médicaments sous surveillance");
        List<MedicamentResponse> medicaments = medicamentService.findMedicamentsSurveillance();
        return ResponseEntity.ok(medicaments);
    }

    // ============================================
    // ENDPOINTS DE GESTION (CRUD)
    // ============================================

    @PostMapping
    @Operation(summary = "Créer un médicament",
            description = "Crée un nouveau médicament dans le référentiel")
    @ApiResponse(responseCode = "201", description = "Médicament créé avec succès")
    @ApiResponse(responseCode = "400", description = "Données invalides")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> createMedicament(
            @Parameter(description = "Données du médicament à créer")
            @Valid @RequestBody CreateMedicamentRequest request) {

        log.info("Création d'un nouveau médicament: {}", request.getCodeCis());
        MedicamentResponse medicament = medicamentService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(medicament);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Modifier un médicament",
            description = "Met à jour les informations d'un médicament existant")
    @ApiResponse(responseCode = "200", description = "Médicament modifié avec succès")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> updateMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id,
            @Parameter(description = "Nouvelles données du médicament")
            @Valid @RequestBody UpdateMedicamentRequest request) {

        log.info("Modification du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.update(id, request);
        return ResponseEntity.ok(medicament);
    }

    @PatchMapping("/{id}/desactiver")
    @Operation(summary = "Désactiver un médicament",
            description = "Désactive un médicament (soft delete)")
    @ApiResponse(responseCode = "204", description = "Médicament désactivé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> desactiverMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.info("Désactivation du médicament: {}", id);
        medicamentService.desactiver(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/reactiver")
    @Operation(summary = "Réactiver un médicament",
            description = "Réactive un médicament précédemment désactivé")
    @ApiResponse(responseCode = "200", description = "Médicament réactivé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MedicamentResponse> reactiverMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.info("Réactivation du médicament: {}", id);
        MedicamentResponse medicament = medicamentService.reactiver(id);
        return ResponseEntity.ok(medicament);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer définitivement un médicament",
            description = "Supprime définitivement un médicament (attention: irréversible)")
    @ApiResponse(responseCode = "204", description = "Médicament supprimé")
    @ApiResponse(responseCode = "404", description = "Médicament non trouvé")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteMedicament(
            @Parameter(description = "ID du médicament") @PathVariable UUID id) {

        log.warn("Suppression définitive du médicament: {}", id);
        medicamentService.deleteDefinitivement(id);
        return ResponseEntity.noContent().build();
    }

    // ============================================
    // ENDPOINTS UTILITAIRES
    // ============================================

    @GetMapping("/count")
    @Operation(summary = "Nombre de médicaments actifs",
            description = "Retourne le nombre total de médicaments actifs")
    @ApiResponse(responseCode = "200", description = "Nombre récupéré")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Long> countMedicamentsActifs() {

        long count = medicamentService.countActifs();
        return ResponseEntity.ok(count);
    }

    @GetMapping("/exists/{codeCis}")
    @Operation(summary = "Vérifier l'existence d'un médicament",
            description = "Vérifie si un médicament existe avec le code CIS donné")
    @ApiResponse(responseCode = "200", description = "Statut d'existence")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Boolean> checkMedicamentExists(
            @Parameter(description = "Code CIS à vérifier") @PathVariable String codeCis) {

        boolean exists = medicamentService.existsByCodeCis(codeCis);
        return ResponseEntity.ok(exists);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/controller/PatientSpecificityController.java

```java
// lims-ref-service/src/main/java/com/lims/referential/controller/PatientSpecificityController.java
package com.lims.referential.controller;

import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import com.lims.referential.service.PatientSpecificityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Contrôleur REST pour la gestion des spécificités patients.
 * Utilisé par le composant PatientSituation du frontend.
 */
@RestController
@RequestMapping("/api/v1/patient-specificities")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Patient Specificities", description = "Gestion des conditions spéciales des patients")
@SecurityRequirement(name = "Bearer Authentication")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class PatientSpecificityController {

    private final PatientSpecificityService patientSpecificityService;

    // ============================================
    // ENDPOINTS POUR LE COMPOSANT PatientSituation
    // ============================================

    /**
     * Récupère toutes les spécificités actives groupées par catégorie
     * Endpoint principal utilisé par PatientSituation
     */
    @GetMapping("/grouped-by-category")
    @Operation(summary = "Spécificités groupées par catégorie",
            description = "Récupère toutes les spécificités actives organisées par catégorie pour le composant PatientSituation")
    @ApiResponse(responseCode = "200", description = "Spécificités récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getSpecificitiesGroupedByCategory() {
        log.info("GET /api/v1/patient-specificities/grouped-by-category");

        Map<String, Object> result = patientSpecificityService.getSpecificitiesGroupedByCategory();
        return ResponseEntity.ok(result);
    }

    /**
     * Récupère toutes les catégories actives avec leurs spécificités
     */
    @GetMapping("/categories-with-specificities")
    @Operation(summary = "Catégories avec spécificités",
            description = "Récupère les catégories actives avec leurs spécificités associées")
    @ApiResponse(responseCode = "200", description = "Catégories récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getCategoriesWithSpecificities() {
        log.info("GET /api/v1/patient-specificities/categories-with-specificities");

        List<Map<String, Object>> categories = patientSpecificityService.getCategoriesWithSpecificities();
        return ResponseEntity.ok(categories);
    }

    /**
     * Recherche de spécificités par catégorie
     */
    @GetMapping("/by-category/{categoryId}")
    @Operation(summary = "Spécificités par catégorie",
            description = "Récupère les spécificités d'une catégorie donnée")
    @ApiResponse(responseCode = "200", description = "Spécificités récupérées")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> getSpecificitiesByCategory(
            @Parameter(description = "ID de la catégorie") @PathVariable String categoryId,
            @PageableDefault(size = 50, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities/by-category/{}", categoryId);

        PagedResponseDTO<PatientSpecificityResponseDTO> result =
                patientSpecificityService.findByCategory(categoryId, pageable);
        return ResponseEntity.ok(result);
    }

    // ============================================
    // ENDPOINTS STANDARD CRUD
    // ============================================

    /**
     * Récupère toutes les spécificités avec pagination
     */
    @GetMapping
    @Operation(summary = "Liste des spécificités patients",
            description = "Récupère toutes les spécificités patients avec pagination")
    @ApiResponse(responseCode = "200", description = "Liste récupérée avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> getAllSpecificities(
            @PageableDefault(size = 20, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities - page: {}, size: {}",
                pageable.getPageNumber(), pageable.getPageSize());

        PagedResponseDTO<PatientSpecificityResponseDTO> result = patientSpecificityService.findAll(pageable);
        return ResponseEntity.ok(result);
    }

    /**
     * Récupère une spécificité par son ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Détail d'une spécificité",
            description = "Récupère le détail d'une spécificité patient par son ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Spécificité trouvée"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> getSpecificityById(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id) {

        log.info("GET /api/v1/patient-specificities/{}", id);

        PatientSpecificityResponseDTO result = patientSpecificityService.findById(id);
        return ResponseEntity.ok(result);
    }

    /**
     * Recherche avec filtres
     */
    @GetMapping("/search")
    @Operation(summary = "Recherche avec filtres",
            description = "Recherche de spécificités avec filtres par catégorie, niveau d'alerte, etc.")
    @ApiResponse(responseCode = "200", description = "Résultats de recherche")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<PatientSpecificityResponseDTO>> searchSpecificities(
            @Parameter(description = "ID de la catégorie") @RequestParam(required = false) String categorie,
            @Parameter(description = "Niveau d'alerte") @RequestParam(required = false) String niveauAlerte,
            @Parameter(description = "Statut actif") @RequestParam(required = false) Boolean actif,
            @Parameter(description = "Terme de recherche") @RequestParam(required = false) String search,
            @PageableDefault(size = 20, sort = "prioritePreleveur", direction = Sort.Direction.DESC) Pageable pageable) {

        log.info("GET /api/v1/patient-specificities/search - catégorie: {}, niveau: {}, actif: {}, search: {}",
                categorie, niveauAlerte, actif, search);

        PagedResponseDTO<PatientSpecificityResponseDTO> result =
                patientSpecificityService.findWithFilters(categorie, niveauAlerte, actif, pageable);
        return ResponseEntity.ok(result);
    }

    // ============================================
    // ENDPOINTS D'ADMINISTRATION (Admin seulement)
    // ============================================

    /**
     * Crée une nouvelle spécificité
     */
    @PostMapping
    @Operation(summary = "Créer une spécificité",
            description = "Crée une nouvelle spécificité patient")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Spécificité créée avec succès"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> createSpecificity(
            @Valid @RequestBody PatientSpecificityRequestDTO requestDTO) {

        log.info("POST /api/v1/patient-specificities - création: {}", requestDTO.getTitre());

        PatientSpecificityResponseDTO result = patientSpecificityService.create(requestDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    /**
     * Met à jour une spécificité existante
     */
    @PutMapping("/{id}")
    @Operation(summary = "Mettre à jour une spécificité",
            description = "Met à jour une spécificité patient existante")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Spécificité mise à jour"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée"),
            @ApiResponse(responseCode = "400", description = "Données invalides")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PatientSpecificityResponseDTO> updateSpecificity(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id,
            @Valid @RequestBody PatientSpecificityRequestDTO requestDTO) {

        log.info("PUT /api/v1/patient-specificities/{} - mise à jour: {}", id, requestDTO.getTitre());

        PatientSpecificityResponseDTO result = patientSpecificityService.update(id, requestDTO);
        return ResponseEntity.ok(result);
    }

    /**
     * Supprime une spécificité
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Supprimer une spécificité",
            description = "Supprime une spécificité patient (soft delete)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Spécificité supprimée"),
            @ApiResponse(responseCode = "404", description = "Spécificité non trouvée")
    })
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteSpecificity(
            @Parameter(description = "ID de la spécificité") @PathVariable UUID id) {

        log.info("DELETE /api/v1/patient-specificities/{}", id);

        patientSpecificityService.delete(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Statistiques sur les spécificités
     */
    @GetMapping("/statistics")
    @Operation(summary = "Statistiques des spécificités",
            description = "Récupère les statistiques sur l'utilisation des spécificités")
    @ApiResponse(responseCode = "200", description = "Statistiques récupérées")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        log.info("GET /api/v1/patient-specificities/statistics");

        Map<String, Object> stats = patientSpecificityService.getStatistics();
        return ResponseEntity.ok(stats);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/controller/ReferentialController.java

```java
// lims-ref-service/src/main/java/com/lims/referential/controller/ReferentialController.java
package com.lims.referential.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Contrôleur de test pour valider l'authentification admin dans le service référentiel.
 */
@RestController
@RequestMapping("/api/v1/referential")
@Tag(name = "Referential", description = "Gestion des données de référence du LIMS")
@SecurityRequirement(name = "Bearer Authentication")
@Slf4j
public class ReferentialController {

    @GetMapping("/health")
    @Operation(summary = "Test de santé du service référentiel",
            description = "Vérifie que le service est opérationnel et que l'authentification admin fonctionne")
    @ApiResponse(responseCode = "200", description = "Service opérationnel")
    @ApiResponse(responseCode = "401", description = "Token JWT invalide ou manquant")
    @ApiResponse(responseCode = "403", description = "Utilisateur non autorisé (admin requis)")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> health(Authentication authentication) {
        log.info("Health check accessed by admin: {}", authentication.getName());

        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "lims-ref-service");
        response.put("timestamp", System.currentTimeMillis());
        response.put("user", authentication.getName());

        // Si c'est un JWT, extraire quelques infos utiles
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            response.put("realm", jwt.getClaimAsString("realm"));
            response.put("userType", jwt.getClaimAsString("user_type"));
            response.put("expiresAt", jwt.getExpiresAt());
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/analyses")
    @Operation(summary = "Liste des analyses disponibles",
            description = "Retourne la liste des analyses de biologie médicale disponibles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getAnalyses() {
        log.info("Fetching analyses list");

        // Exemple de données de référence (à remplacer par une vraie base)
        List<Map<String, Object>> analyses = List.of(
                Map.of("code", "BIO001", "nom", "Numération Formule Sanguine", "prix", 25.50),
                Map.of("code", "BIO002", "nom", "Glycémie à jeun", "prix", 15.30),
                Map.of("code", "BIO003", "nom", "Cholestérol total", "prix", 18.20),
                Map.of("code", "BIO004", "nom", "Créatininémie", "prix", 12.00)
        );

        return ResponseEntity.ok(analyses);
    }

    @GetMapping("/laboratoires")
    @Operation(summary = "Liste des laboratoires partenaires",
            description = "Retourne la liste des laboratoires référencés dans le système")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getLaboratoires() {
        log.info("Fetching laboratories list");

        // Exemple de données (à remplacer par une vraie base)
        List<Map<String, Object>> laboratoires = List.of(
                Map.of("id", "LAB001", "nom", "Laboratoire Central Paris", "ville", "Paris", "actif", true),
                Map.of("id", "LAB002", "nom", "Biolab Lyon", "ville", "Lyon", "actif", true),
                Map.of("id", "LAB003", "nom", "Lab Provence", "ville", "Marseille", "actif", false)
        );

        return ResponseEntity.ok(laboratoires);
    }

    @PostMapping("/analyses")
    @Operation(summary = "Créer une nouvelle analyse",
            description = "Ajoute une nouvelle analyse au référentiel")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> createAnalyse(@RequestBody Map<String, Object> analyse) {
        log.info("Creating new analyse: {}", analyse);

        // Validation basique
        if (!analyse.containsKey("code") || !analyse.containsKey("nom")) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Code et nom sont obligatoires"));
        }

        // Ici on sauvegarderait en base
        log.info("Analyse créée avec succès: {}", analyse.get("code"));

        return ResponseEntity.ok(Map.of("message", "Analyse créée avec succès"));
    }

    @GetMapping("/admin-info")
    @Operation(summary = "Informations sur l'admin connecté",
            description = "Retourne les détails de l'administrateur connecté")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminInfo(Authentication authentication) {
        log.info("Admin info requested by: {}", authentication.getName());

        Map<String, Object> adminInfo = new HashMap<>();
        adminInfo.put("username", authentication.getName());
        adminInfo.put("authorities", authentication.getAuthorities());

        if (authentication.getPrincipal() instanceof Jwt jwt) {
            adminInfo.put("realm", jwt.getClaimAsString("realm"));
            adminInfo.put("userType", jwt.getClaimAsString("user_type"));
            adminInfo.put("subject", jwt.getSubject());
            adminInfo.put("issuedAt", jwt.getIssuedAt());
            adminInfo.put("expiresAt", jwt.getExpiresAt());

            // Claims spécifiques aux admins
            adminInfo.put("permissions", jwt.getClaimAsStringList("permissions"));
            adminInfo.put("adminLevel", jwt.getClaimAsString("admin_level"));
        }

        return ResponseEntity.ok(adminInfo);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/controller/SpecificityCategoryController.java

```java
// lims-ref-service/src/main/java/com/lims/referential/controller/SpecificityCategoryController.java
package com.lims.referential.controller;

import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import com.lims.referential.service.SpecificityCategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Contrôleur REST pour la gestion des catégories de spécificités patients.
 * Utilisé par le composant PatientSituation pour organiser les conditions spéciales.
 */
@RestController
@RequestMapping("/api/v1/specificity-categories")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Specificity Categories", description = "Gestion des catégories de conditions spéciales")
@SecurityRequirement(name = "Bearer Authentication")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class SpecificityCategoryController {

    private final SpecificityCategoryService specificityCategoryService;

    /**
     * Récupère toutes les catégories actives
     * Endpoint principal pour PatientSituation
     */
    @GetMapping
    @Operation(summary = "Liste des catégories de spécificités",
            description = "Récupère toutes les catégories actives triées par ordre d'affichage")
    @ApiResponse(responseCode = "200", description = "Catégories récupérées avec succès")
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<List<SpecificityCategoryResponseDTO>> getAllCategories() {
        log.info("GET /api/v1/specificity-categories");

        List<SpecificityCategoryResponseDTO> categories = specificityCategoryService.findAllActive();
        return ResponseEntity.ok(categories);
    }

    /**
     * Récupère une catégorie par son ID
     */
    @GetMapping("/{id}")
    @Operation(summary = "Détail d'une catégorie",
            description = "Récupère le détail d'une catégorie de spécificité par son ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Catégorie trouvée"),
            @ApiResponse(responseCode = "404", description = "Catégorie non trouvée")
    })
    @PreAuthorize("hasRole('STAFF') or hasRole('ADMIN')")
    public ResponseEntity<SpecificityCategoryResponseDTO> getCategoryById(
            @Parameter(description = "ID de la catégorie") @PathVariable String id) {

        log.info("GET /api/v1/specificity-categories/{}", id);

        SpecificityCategoryResponseDTO category = specificityCategoryService.findById(id);
        return ResponseEntity.ok(category);
    }

    /**
     * Récupère les statistiques des catégories
     */
    @GetMapping("/statistics")
    @Operation(summary = "Statistiques des catégories",
            description = "Récupère les statistiques d'utilisation des catégories")
    @ApiResponse(responseCode = "200", description = "Statistiques récupérées")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getCategoryStatistics() {
        log.info("GET /api/v1/specificity-categories/statistics");

        Map<String, Object> stats = specificityCategoryService.getStatistics();
        return ResponseEntity.ok(stats);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/ApiResponseDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class ApiResponseDTO<T> {

    private boolean success;
    private String message;
    private T data;
    private LocalDateTime timestamp;
    private String path;

    public static <T> ApiResponseDTO<T> success(T data) {
        return ApiResponseDTO.<T>builder()
                .success(true)
                .message("Opération réussie")
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static <T> ApiResponseDTO<T> success(T data, String message) {
        return ApiResponseDTO.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static ApiResponseDTO<Void> success(String message) {
        return ApiResponseDTO.<Void>builder()
                .success(true)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static <T> ApiResponseDTO<T> error(String message) {
        return ApiResponseDTO.<T>builder()
                .success(false)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static <T> ApiResponseDTO<T> error(String message, String path) {
        return ApiResponseDTO.<T>builder()
                .success(false)
                .message(message)
                .path(path)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/CacheStatsDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
public class CacheStatsDTO {

    private String cacheName;
    private Long hitCount;
    private Long missCount;
    private Long evictionCount;
    private Double hitRatio;
    private Long estimatedSize;
    private LocalDateTime lastAccess;
    private Map<String, Object> additionalMetrics;

    public static CacheStatsDTO of(String cacheName, Map<String, Object> stats) {
        return CacheStatsDTO.builder()
                .cacheName(cacheName)
                .hitCount((Long) stats.getOrDefault("hitCount", 0L))
                .missCount((Long) stats.getOrDefault("missCount", 0L))
                .evictionCount((Long) stats.getOrDefault("evictionCount", 0L))
                .hitRatio((Double) stats.getOrDefault("hitRatio", 0.0))
                .estimatedSize((Long) stats.getOrDefault("estimatedSize", 0L))
                .lastAccess(LocalDateTime.now())
                .additionalMetrics(stats)
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/DistanceCalculationDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class DistanceCalculationDTO {

    private PointDTO origin;
    private PointDTO destination;
    private BigDecimal distanceKm;
    private BigDecimal distanceMiles;
    private String unit;
    private LocalDateTime calculatedAt;

    @Data
    @Builder
    public static class PointDTO {
        private BigDecimal latitude;
        private BigDecimal longitude;
        private String label;
        private String address;
    }

    public static DistanceCalculationDTO of(
            BigDecimal originLat, BigDecimal originLon,
            BigDecimal destLat, BigDecimal destLon,
            BigDecimal distanceKm) {

        return DistanceCalculationDTO.builder()
                .origin(PointDTO.builder()
                        .latitude(originLat)
                        .longitude(originLon)
                        .build())
                .destination(PointDTO.builder()
                        .latitude(destLat)
                        .longitude(destLon)
                        .build())
                .distanceKm(distanceKm)
                .distanceMiles(distanceKm.multiply(new BigDecimal("0.621371")))
                .unit("km")
                .calculatedAt(LocalDateTime.now())
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/ErrorResponseDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ErrorResponseDTO {

    private LocalDateTime timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
    private Map<String, List<String>> validationErrors;

    public static ErrorResponseDTO of(int status, String error, String message, String path) {
        return ErrorResponseDTO.builder()
                .timestamp(LocalDateTime.now())
                .status(status)
                .error(error)
                .message(message)
                .path(path)
                .build();
    }

    public static ErrorResponseDTO withValidationErrors(int status, String error, String message, String path, Map<String, List<String>> validationErrors) {
        return ErrorResponseDTO.builder()
                .timestamp(LocalDateTime.now())
                .status(status)
                .error(error)
                .message(message)
                .path(path)
                .validationErrors(validationErrors)
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/ExportRequestDTO.java

```java
package com.lims.referential.dto.common;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class ExportRequestDTO {

    @NotBlank(message = "Le format d'export est obligatoire")
    private String format; // csv, excel, json

    private List<String> columns;
    private Map<String, Object> filters;
    private String sortBy;
    private String sortDirection;
    private Integer maxRecords;
    private boolean includeHeaders;

    @Builder.Default
    private String encoding = "UTF-8";

    @Builder.Default
    private String delimiter = ",";
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/ImportResultDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ImportResultDTO {

    private boolean success;
    private Integer totalRecords;
    private Integer successCount;
    private Integer errorCount;
    private Integer skippedCount;
    private List<String> errors;
    private Map<String, Object> summary;
    private LocalDateTime importedAt;
    private String filename;

    public static ImportResultDTO success(int total, int success, int errors, int skipped, String filename) {
        return ImportResultDTO.builder()
                .success(errors == 0)
                .totalRecords(total)
                .successCount(success)
                .errorCount(errors)
                .skippedCount(skipped)
                .filename(filename)
                .importedAt(LocalDateTime.now())
                .summary(Map.of(
                        "successRate", total > 0 ? (double) success / total * 100 : 0,
                        "hasErrors", errors > 0
                ))
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/InteractionCheckDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class InteractionCheckDTO {

    private UUID medicamentId;
    private String medicamentNom;
    private List<String> analysesTestees;
    private List<InteractionDTO> interactionsDetectees;
    private String niveauCriticitéGlobal;
    private boolean arretRequis;
    private Integer delaiArretMaxHeures;
    private List<String> recommandations;
    private LocalDateTime checkedAt;

    @Data
    @Builder
    public static class InteractionDTO {
        private String codeNabm;
        private String nomAnalyse;
        private String typeInteraction;
        private String niveauCriticite;
        private String description;
        private Integer delaiArret;
        private String recommandation;
    }

    public static InteractionCheckDTO of(UUID medicamentId, String medicamentNom, List<String> analysesTestees) {
        return InteractionCheckDTO.builder()
                .medicamentId(medicamentId)
                .medicamentNom(medicamentNom)
                .analysesTestees(analysesTestees)
                .checkedAt(LocalDateTime.now())
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/PagedResponseDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.domain.Page;

import java.util.List;

@Data
@Builder
public class PagedResponseDTO<T> {

    private List<T> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private boolean first;
    private boolean last;
    private boolean empty;

    public static <T> PagedResponseDTO<T> from(Page<T> page) {
        return PagedResponseDTO.<T>builder()
                .content(page.getContent())
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .first(page.isFirst())
                .last(page.isLast())
                .empty(page.isEmpty())
                .build();
    }

    public static <T> PagedResponseDTO<T> of(List<T> content, int page, int size, long totalElements) {
        int totalPages = (int) Math.ceil((double) totalElements / size);

        return PagedResponseDTO.<T>builder()
                .content(content)
                .page(page)
                .size(size)
                .totalElements(totalElements)
                .totalPages(totalPages)
                .first(page == 0)
                .last(page >= totalPages - 1)
                .empty(content.isEmpty())
                .build();
    }

    public static <T> PagedResponseDTO<T> empty(int page, int size) {
        return PagedResponseDTO.<T>builder()
                .content(List.of())
                .page(page)
                .size(size)
                .totalElements(0L)
                .totalPages(0)
                .first(true)
                .last(true)
                .empty(true)
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/SearchCriteriaDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class SearchCriteriaDTO {

    private String searchTerm;
    private Map<String, Object> filters;
    private Integer page;
    private Integer size;
    private String sortBy;
    private String sortDirection;

    public static SearchCriteriaDTO of(String searchTerm, int page, int size, String sort) {
        String[] sortParts = sort != null ? sort.split(",") : new String[]{"id", "asc"};
        String sortBy = sortParts.length > 0 ? sortParts[0] : "id";
        String sortDirection = sortParts.length > 1 ? sortParts[1] : "asc";

        return SearchCriteriaDTO.builder()
                .searchTerm(searchTerm)
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDirection(sortDirection)
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/StatisticsDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
public class StatisticsDTO {

    private String domain;
    private Map<String, Object> metrics;
    private LocalDateTime generatedAt;
    private String period;

    public static StatisticsDTO of(String domain, Map<String, Object> metrics) {
        return StatisticsDTO.builder()
                .domain(domain)
                .metrics(metrics)
                .generatedAt(LocalDateTime.now())
                .period("current")
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/SuggestionDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
public class SuggestionDTO {

    private UUID id;
    private String value;
    private String label;
    private String description;
    private String category;
    private Integer relevanceScore;
    private Object metadata;

    public static SuggestionDTO of(UUID id, String value, String label) {
        return SuggestionDTO.builder()
                .id(id)
                .value(value)
                .label(label)
                .relevanceScore(100)
                .build();
    }

    public static SuggestionDTO of(UUID id, String value, String label, String description) {
        return SuggestionDTO.builder()
                .id(id)
                .value(value)
                .label(label)
                .description(description)
                .relevanceScore(100)
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/common/ValidationResultDTO.java

```java
package com.lims.referential.dto.common;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ValidationResultDTO {

    private boolean valid;
    private String field;
    private Object value;
    private String message;
    private String errorCode;
    private List<String> suggestions;
    private Map<String, Object> context;
    private LocalDateTime validatedAt;

    public static ValidationResultDTO valid(String field, Object value) {
        return ValidationResultDTO.builder()
                .valid(true)
                .field(field)
                .value(value)
                .message("Validation réussie")
                .validatedAt(LocalDateTime.now())
                .build();
    }

    public static ValidationResultDTO invalid(String field, Object value, String message) {
        return ValidationResultDTO.builder()
                .valid(false)
                .field(field)
                .value(value)
                .message(message)
                .validatedAt(LocalDateTime.now())
                .build();
    }

    public static ValidationResultDTO invalid(String field, Object value, String message, String errorCode) {
        return ValidationResultDTO.builder()
                .valid(false)
                .field(field)
                .value(value)
                .message(message)
                .errorCode(errorCode)
                .validatedAt(LocalDateTime.now())
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/AnalyseRequestDTO.java

```java
package com.lims.referential.dto.request;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.enums.analyses.NiveauUrgence;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AnalyseRequestDTO {

    @NotBlank(message = "Le code NABM est obligatoire")
    @Size(max = 10, message = "Le code NABM ne peut pas dépasser 10 caractères")
    private String codeNabm;

    @NotBlank(message = "Le libellé est obligatoire")
    @Size(max = 255, message = "Le libellé ne peut pas dépasser 255 caractères")
    private String libelle;

    @Size(max = 50, message = "Le libellé abrégé ne peut pas dépasser 50 caractères")
    private String libelleAbrege;

    private String description;

    @NotNull(message = "La catégorie est obligatoire")
    private CategorieAnalyse categorie;

    private String sousCategorie;
    private String methodeTechnique;
    private String uniteResultat;

    @Valid
    private Analyse.ValeursNormales valeursNormales;

    @Valid
    @NotNull(message = "Le délai de rendu est obligatoire")
    private Analyse.DelaiRendu delaiRendu;

    @Valid
    private List<Analyse.TubeRequis> tubesRequis;

    @Valid
    private Analyse.ConditionsPreAnalytiques conditionsPreAnalytiques;

    @Valid
    private Analyse.Tarif tarif;

    private NiveauUrgence niveauUrgence = NiveauUrgence.NORMAL;
    private List<String> analysesAssociees;
    private List<String> contraindicationsRelatives;
    private String observationsSpeciales;
    private Boolean actif = true;
}

```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/BulkOperationRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class BulkOperationRequestDTO {

    @NotNull(message = "L'opération est obligatoire")
    private String operation; // UPDATE, DELETE, ACTIVATE, DEACTIVATE

    @NotEmpty(message = "Au moins un ID doit être spécifié")
    private List<UUID> ids;

    private Map<String, Object> parameters; // Paramètres pour l'opération

    @Builder.Default
    private Boolean validateBeforeOperation = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/CachePreloadRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CachePreloadRequestDTO {

    @NotEmpty(message = "Au moins un domaine doit être spécifié")
    private List<String> domaines;

    @Builder.Default
    private Boolean forcer = false; // Vider avant de précharger

    @Builder.Default
    private Boolean asynchrone = true;

    @Builder.Default
    private Integer batchSize = 100;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/CreateMedicamentRequest.java

```java
package com.lims.referential.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO pour créer un nouveau médicament
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Données pour créer un nouveau médicament")
public class CreateMedicamentRequest {

    @NotBlank(message = "Le code CIS est obligatoire")
    @Size(max = 50, message = "Le code CIS ne peut pas dépasser 50 caractères")
    @Schema(description = "Code CIS du médicament", example = "CIS12345678", required = true)
    private String codeCis;

    @NotBlank(message = "La dénomination est obligatoire")
    @Size(max = 500, message = "La dénomination ne peut pas dépasser 500 caractères")
    @Schema(description = "Dénomination du médicament", example = "DOLIPRANE 500 mg, comprimé", required = true)
    private String denomination;

    @Size(max = 200, message = "La forme pharmaceutique ne peut pas dépasser 200 caractères")
    @Schema(description = "Forme pharmaceutique", example = "comprimé")
    private String formePharma;

    @Size(max = 200, message = "Les voies d'administration ne peuvent pas dépasser 200 caractères")
    @Schema(description = "Voies d'administration", example = "orale")
    private String voiesAdmin;

    @Size(max = 100, message = "Le statut AMM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut AMM", example = "Autorisation active")
    private String statutAmm;

    @Size(max = 100, message = "Le type de procédure ne peut pas dépasser 100 caractères")
    @Schema(description = "Type de procédure AMM", example = "Procédure nationale")
    private String typeProcedure;

    @Size(max = 300, message = "Le laboratoire titulaire ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire titulaire", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireTitulaire;

    @Size(max = 300, message = "Le laboratoire exploitant ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire exploitant", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireExploitant;

    @Schema(description = "Date AMM", example = "1985-07-25T00:00:00")
    private LocalDateTime dateAmm;

    @Size(max = 100, message = "Le statut BdM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut BdM", example = "Commercialisé")
    private String statutBdm;

    @Size(max = 100, message = "Le numéro autorisation européenne ne peut pas dépasser 100 caractères")
    @Schema(description = "Numéro autorisation européenne", example = "EU/1/15/1234/001")
    private String numeroAutorisationEuropeenne;

    @Size(max = 500, message = "Les titulaires AMM ne peuvent pas dépasser 500 caractères")
    @Schema(description = "Titulaires AMM", example = "SANOFI AVENTIS FRANCE")
    private String titulairesAmm;

    @Schema(description = "Surveillance renforcée", example = "false")
    private Boolean surveillanceRenforcee = false;

    @DecimalMin(value = "0.0", message = "Le prix de vente doit être positif")
    @Digits(integer = 10, fraction = 2, message = "Le prix de vente ne peut avoir plus de 2 décimales")
    @Schema(description = "Prix de vente public", example = "2.18")
    private BigDecimal prixVente;

    @Min(value = 0, message = "Le taux de remboursement doit être positif")
    @Max(value = 100, message = "Le taux de remboursement ne peut pas dépasser 100%")
    @Schema(description = "Taux de remboursement", example = "65")
    private Integer tauxRemboursement;

    @Builder.Default
    @Schema(description = "Indique si le médicament est actif", example = "true")
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/GeographiqueRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
public class GeographiqueRequestDTO {

    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10, message = "Le code postal ne peut pas dépasser 10 caractères")
    private String codePostal;

    @NotBlank(message = "Le nom de la commune est obligatoire")
    @Size(max = 255, message = "Le nom de la commune ne peut pas dépasser 255 caractères")
    private String nomCommune;

    @Size(max = 10, message = "Le code commune ne peut pas dépasser 10 caractères")
    private String codeCommune;

    // Hiérarchie administrative
    @NotBlank(message = "Le département est obligatoire")
    @Size(max = 100, message = "Le département ne peut pas dépasser 100 caractères")
    private String departement;

    @NotBlank(message = "Le code département est obligatoire")
    @Size(max = 3, message = "Le code département ne peut pas dépasser 3 caractères")
    private String codeDepartement;

    @NotBlank(message = "La région est obligatoire")
    @Size(max = 100, message = "La région ne peut pas dépasser 100 caractères")
    private String region;

    @NotBlank(message = "Le code région est obligatoire")
    @Size(max = 3, message = "Le code région ne peut pas dépasser 3 caractères")
    private String codeRegion;

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Informations démographiques
    private Integer population;
    private BigDecimal superficieKm2;
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    private List<String> laboratoiresZone; // Array des IDs laboratoires
    private BigDecimal distanceLaboratoirePlusProcheKm;

    @Builder.Default
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/GeolocationSearchRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

@Data
@Builder
public class GeolocationSearchRequestDTO {

    @NotNull(message = "La latitude est obligatoire")
    @DecimalMin(value = "-90.0", message = "La latitude doit être comprise entre -90 et 90")
    @DecimalMax(value = "90.0", message = "La latitude doit être comprise entre -90 et 90")
    private BigDecimal latitude;

    @NotNull(message = "La longitude est obligatoire")
    @DecimalMin(value = "-180.0", message = "La longitude doit être comprise entre -180 et 180")
    @DecimalMax(value = "180.0", message = "La longitude doit être comprise entre -180 et 180")
    private BigDecimal longitude;

    @Builder.Default
    private Integer radius = 10; // en kilomètres

    @Builder.Default
    private String unite = "km"; // km ou miles

    @Builder.Default
    private Integer maxResults = 50;

    private String typeRecherche; // laboratoires, pharmacies, hopitaux
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/LaboratoireRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class LaboratoireRequestDTO {

    @NotBlank(message = "Le nom du laboratoire est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Size(max = 500, message = "La description ne peut pas dépasser 500 caractères")
    private String description;

    @NotBlank(message = "L'adresse est obligatoire")
    @Size(max = 500, message = "L'adresse ne peut pas dépasser 500 caractères")
    private String adresse;

    @NotBlank(message = "La ville est obligatoire")
    @Size(max = 100, message = "La ville ne peut pas dépasser 100 caractères")
    private String ville;

    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10, message = "Le code postal ne peut pas dépasser 10 caractères")
    private String codePostal;

    @Size(max = 100, message = "Le pays ne peut pas dépasser 100 caractères")
    private String pays;

    // Informations de contact (mappées vers les propriétés de l'entité)
    @Valid
    private ContactDTO contact;

    // Informations pratiques
    @Valid
    private InformationsPratiquesDTO informationsPratiques;

    // Capacités techniques
    @Valid
    private CapacitesTechniquesDTO capacitesTechniques;

    @Builder.Default
    private Boolean actif = true;

    // ============================================
    // DTOs IMBRIQUÉS
    // ============================================

    @Data
    @Builder
    public static class ContactDTO {
        @Size(max = 20, message = "Le téléphone ne peut pas dépasser 20 caractères")
        private String telephone;

        @Size(max = 20, message = "Le fax ne peut pas dépasser 20 caractères")
        private String fax;

        @Size(max = 255, message = "L'email ne peut pas dépasser 255 caractères")
        private String email;

        @Size(max = 255, message = "L'URL du site web ne peut pas dépasser 255 caractères")
        private String siteWeb;
    }

    @Data
    @Builder
    public static class InformationsPratiquesDTO {
        @Size(max = 500, message = "Les horaires ne peuvent pas dépasser 500 caractères")
        private String horairesOuverture;

        @Builder.Default
        private Boolean parkingDisponible = false;

        @Builder.Default
        private Boolean accesHandicapes = false;

        @Size(max = 255, message = "Les infos transport ne peuvent pas dépasser 255 caractères")
        private String transportPublic;
    }

    @Data
    @Builder
    public static class CapacitesTechniquesDTO {
        private List<String> analysesDisponibles;
        private List<String> specialitesTechniques;
        private List<String> equipementsSpeciaux;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/MedecinRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.util.List;

@Data
@Builder
public class MedecinRequestDTO {

    @NotBlank(message = "Le numéro RPPS est obligatoire")
    @Pattern(regexp = "\\d{11}", message = "Le numéro RPPS doit contenir exactement 11 chiffres")
    private String numeroRpps;

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 100, message = "Le nom ne peut pas dépasser 100 caractères")
    private String nom;

    @NotBlank(message = "Le prénom est obligatoire")
    @Size(max = 100, message = "Le prénom ne peut pas dépasser 100 caractères")
    private String prenom;

    @Size(max = 20, message = "Le titre ne peut pas dépasser 20 caractères")
    private String titre;

    @Size(max = 100, message = "La spécialité ne peut pas dépasser 100 caractères")
    private String specialitePrincipale;

    private List<String> specialitesSecondaires;

    // Adresse professionnelle
    @Valid
    private AdresseRequestDTO adresse;

    // Contact professionnel
    @Valid
    private ContactRequestDTO contact;

    @Size(max = 50, message = "Le mode d'exercice ne peut pas dépasser 50 caractères")
    private String modeExercice; // liberal, salarie, mixte

    private Integer secteurConventionnel; // 1, 2, 3

    private LocalDate dateInstallation;

    private Boolean actif = true;

    @Data
    @Builder
    public static class AdresseRequestDTO {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Pattern(regexp = "\\d{5}", message = "Le code postal doit contenir 5 chiffres")
        @Size(max = 10)
        private String codePostal;

        @Size(max = 100)
        private String ville;

        @Size(max = 100)
        private String departement;

        @Size(max = 100)
        private String region;

        @Builder.Default
        @Size(max = 50)
        private String pays = "France";
    }

    @Data
    @Builder
    public static class ContactRequestDTO {
        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de téléphone invalide")
        private String telephone;

        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de fax invalide")
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/MedicamentRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class MedicamentRequestDTO {

    @NotBlank(message = "Le nom commercial est obligatoire")
    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    private String nomCommercial;

    @NotBlank(message = "La DCI est obligatoire")
    @Size(max = 255, message = "La DCI ne peut pas dépasser 255 caractères")
    private String dci; // Dénomination Commune Internationale

    @Size(max = 13, message = "Le code CIP ne peut pas dépasser 13 caractères")
    private String codeCip;

    // Classification
    @Size(max = 100, message = "La classe thérapeutique ne peut pas dépasser 100 caractères")
    private String classeTherapeutique;

    @Size(max = 100, message = "La sous-classe ne peut pas dépasser 100 caractères")
    private String sousClasse;

    @Size(max = 100, message = "La forme pharmaceutique ne peut pas dépasser 100 caractères")
    private String formePharmaceutique;

    @Size(max = 100, message = "Le dosage ne peut pas dépasser 100 caractères")
    private String dosage;

    @Size(max = 100, message = "La voie d'administration ne peut pas dépasser 100 caractères")
    private String voieAdministration;

    // Interactions avec analyses
    private List<String> analysesImpactees; // Array des codes NABM

    @Size(max = 50, message = "Le type d'interaction ne peut pas dépasser 50 caractères")
    private String typeInteraction; // interference, faux_positif, faux_negatif

    @Size(max = 20, message = "Le niveau de criticité ne peut pas dépasser 20 caractères")
    private String niveauCriticite; // faible, modere, eleve, critique

    // Délais pré-analytiques
    @Builder.Default
    private Boolean arretRequis = false;

    @Builder.Default
    private Integer delaiArretHeures = 0;

    private String instructionsArret;

    // Informations complémentaires
    @Size(max = 255, message = "Le principe actif ne peut pas dépasser 255 caractères")
    private String principeActif;

    @Size(max = 255, message = "Le laboratoire fabricant ne peut pas dépasser 255 caractères")
    private String laboratoireFabricant;

    @Size(max = 50, message = "Le statut de commercialisation ne peut pas dépasser 50 caractères")
    private String statutCommercialisation; // commercialise, arrete, suspendu

    @Builder.Default
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/MutuelleRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class MutuelleRequestDTO {

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    private String nomCommercial;

    @Size(max = 14, message = "Le SIRET ne peut pas dépasser 14 caractères")
    private String siret;

    // Classification
    @Size(max = 50, message = "Le type d'organisme ne peut pas dépasser 50 caractères")
    private String typeOrganisme; // cpam, mutuelle, assurance, cmuc

    @Size(max = 20, message = "Le code organisme ne peut pas dépasser 20 caractères")
    private String codeOrganisme;

    @Size(max = 100, message = "Le régime de rattachement ne peut pas dépasser 100 caractères")
    private String regimeRattachement;

    // Coordonnées
    @Valid
    private AdresseMutuelleRequestDTO adresse;

    // Contact
    @Valid
    private ContactMutuelleRequestDTO contact;

    // Informations de prise en charge
    @Valid
    private PriseEnChargeRequestDTO priseEnCharge;

    // Facturation
    @Valid
    private FacturationRequestDTO facturation;

    // Conventions spéciales
    private List<String> conventionsSpeciales;

    @Builder.Default
    private Boolean actif = true;

    @Data
    @Builder
    public static class AdresseMutuelleRequestDTO {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Size(max = 10)
        private String codePostal;

        @Size(max = 100)
        private String ville;

        @Size(max = 100)
        private String departement;

        @Size(max = 100)
        private String region;
    }

    @Data
    @Builder
    public static class ContactMutuelleRequestDTO {
        private String telephone;
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;

        @Size(max = 255)
        private String siteWeb;
    }

    @Data
    @Builder
    public static class PriseEnChargeRequestDTO {
        @Builder.Default
        private BigDecimal tauxBaseRemboursement = new BigDecimal("70.00");

        private BigDecimal plafondAnnuelEuro;

        @Builder.Default
        private BigDecimal franchiseEuro = BigDecimal.ZERO;

        private List<AnalyseCouvertureRequestDTO> analysesCouvertes;
        private List<String> analysesExclues;
    }

    @Data
    @Builder
    public static class FacturationRequestDTO {
        private Map<String, Object> codesFacturation;

        @Builder.Default
        private Integer delaiPaiementJours = 30;

        @Size(max = 50)
        private String modeTransmission; // noemie, edifact, papier
    }

    @Data
    @Builder
    public static class AnalyseCouvertureRequestDTO {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/PatientSpecificityRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class PatientSpecificityRequestDTO {

    @NotBlank(message = "Le titre est obligatoire")
    @Size(max = 255, message = "Le titre ne peut pas dépasser 255 caractères")
    private String titre;

    private String description;

    @Size(max = 50, message = "L'ID de catégorie ne peut pas dépasser 50 caractères")
    private String categoryId;

    // Niveau d'alerte
    @NotBlank(message = "Le niveau d'alerte est obligatoire")
    @Size(max = 20, message = "Le niveau d'alerte ne peut pas dépasser 20 caractères")
    private String niveauAlerte; // normal, warning, critical

    @Size(max = 50, message = "L'icône ne peut pas dépasser 50 caractères")
    private String icone;

    // Mots-clés pour recherche
    private List<String> motsCles;

    // Instructions associées
    private String instructionsPreleveur;
    private String instructionsTechnique;
    private String instructionsAdministrative;

    // Contraintes pré-analytiques
    private List<String> impactPrelevements;
    private List<String> analysesContreIndiquees;
    private List<String> analysesModifiees;

    // Priorité et temps
    @Builder.Default
    private Integer prioritePreleveur = 1; // 1=normale, 2=prioritaire, 3=urgente

    @Builder.Default
    private Integer tempsSupplementaireMinutes = 0;

    @Builder.Default
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/SpecificityCategoryRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SpecificityCategoryRequestDTO {

    @NotBlank(message = "L'ID de la catégorie est obligatoire")
    @Size(max = 50, message = "L'ID ne peut pas dépasser 50 caractères")
    private String id;

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    private String description;

    @Size(max = 7, message = "La couleur doit être un code hex valide")
    private String couleur; // Code couleur hex

    @Size(max = 50, message = "L'icône ne peut pas dépasser 50 caractères")
    private String icone;

    @Builder.Default
    private Integer ordreAffichage = 0;

    @Builder.Default
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/SynchronisationRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class SynchronisationRequestDTO {

    @NotEmpty(message = "Au moins un domaine doit être spécifié")
    private List<String> domaines; // analyses, medecins, laboratoires, etc.

    @NotNull(message = "Le mode de synchronisation est obligatoire")
    @Builder.Default
    private String modeSync = "INCREMENTAL"; // INCREMENTAL, FULL

    @Builder.Default
    private Boolean forcerRemplacement = false;

    @Builder.Default
    private Boolean notifierResultat = true;

    private String sourceExterne; // URL ou nom de la source
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/TourneeOptimisationRequestDTO.java

```java
package com.lims.referential.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.List;

@Data
@Builder
public class TourneeOptimisationRequestDTO {

    @NotNull(message = "Le point de départ est obligatoire")
    @Valid
    private PointVisiteRequestDTO pointDepart;

    @NotNull(message = "La liste des points de visite est obligatoire")
    @Size(min = 1, message = "Au moins un point de visite est requis")
    @Valid
    private List<PointVisiteRequestDTO> pointsVisite;

    private LocalTime heureDepart;

    @Builder.Default
    private String optimiserPour = "DISTANCE"; // DISTANCE, TEMPS, COUT

    @Builder.Default
    private Integer vitesseMoyenneKmH = 50;

    @Builder.Default
    private Boolean retourAuDepart = true;

    @Data
    @Builder
    public static class PointVisiteRequestDTO {
        @NotNull(message = "La latitude est obligatoire")
        private BigDecimal latitude;

        @NotNull(message = "La longitude est obligatoire")
        private BigDecimal longitude;

        @Size(max = 255, message = "L'adresse ne peut pas dépasser 255 caractères")
        private String adresse;

        @Builder.Default
        private Integer dureeVisite = 15; // en minutes

        @Builder.Default
        private Integer priorite = 1; // 1=normale, 2=prioritaire, 3=urgente

        private String commentaire;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/request/UpdateMedicamentRequest.java

```java
package com.lims.referential.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO pour mettre à jour un médicament existant
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Données pour mettre à jour un médicament existant")
public class UpdateMedicamentRequest {

    @Size(max = 500, message = "La dénomination ne peut pas dépasser 500 caractères")
    @Schema(description = "Dénomination du médicament", example = "DOLIPRANE 500 mg, comprimé")
    private String denomination;

    @Size(max = 200, message = "La forme pharmaceutique ne peut pas dépasser 200 caractères")
    @Schema(description = "Forme pharmaceutique", example = "comprimé")
    private String formePharma;

    @Size(max = 200, message = "Les voies d'administration ne peuvent pas dépasser 200 caractères")
    @Schema(description = "Voies d'administration", example = "orale")
    private String voiesAdmin;

    @Size(max = 100, message = "Le statut AMM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut AMM", example = "Autorisation active")
    private String statutAmm;

    @Size(max = 100, message = "Le type de procédure ne peut pas dépasser 100 caractères")
    @Schema(description = "Type de procédure AMM", example = "Procédure nationale")
    private String typeProcedure;

    @Size(max = 300, message = "Le laboratoire titulaire ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire titulaire", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireTitulaire;

    @Size(max = 300, message = "Le laboratoire exploitant ne peut pas dépasser 300 caractères")
    @Schema(description = "Laboratoire exploitant", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireExploitant;

    @Schema(description = "Date AMM", example = "1985-07-25T00:00:00")
    private LocalDateTime dateAmm;

    @Size(max = 100, message = "Le statut BdM ne peut pas dépasser 100 caractères")
    @Schema(description = "Statut BdM", example = "Commercialisé")
    private String statutBdm;

    @Size(max = 100, message = "Le numéro autorisation européenne ne peut pas dépasser 100 caractères")
    @Schema(description = "Numéro autorisation européenne", example = "EU/1/15/1234/001")
    private String numeroAutorisationEuropeenne;

    @Size(max = 500, message = "Les titulaires AMM ne peuvent pas dépasser 500 caractères")
    @Schema(description = "Titulaires AMM", example = "SANOFI AVENTIS FRANCE")
    private String titulairesAmm;

    @Schema(description = "Surveillance renforcée", example = "false")
    private Boolean surveillanceRenforcee;

    @DecimalMin(value = "0.0", message = "Le prix de vente doit être positif")
    @Digits(integer = 10, fraction = 2, message = "Le prix de vente ne peut avoir plus de 2 décimales")
    @Schema(description = "Prix de vente public", example = "2.18")
    private BigDecimal prixVente;

    @Min(value = 0, message = "Le taux de remboursement doit être positif")
    @Max(value = 100, message = "Le taux de remboursement ne peut pas dépasser 100%")
    @Schema(description = "Taux de remboursement", example = "65")
    private Integer tauxRemboursement;

    @Schema(description = "Indique si le médicament est actif", example = "true")
    private Boolean actif;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/AnalyseInteractionResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class AnalyseInteractionResponseDTO {

    private List<String> analysesTestees;
    private List<InteractionDetailDTO> interactions;
    private String niveauCriticitéGlobal;
    private List<String> recommandationsGenerales;
    private LocalDateTime analyseLe;

    @Data
    @Builder
    public static class InteractionDetailDTO {
        private String codeNabm;
        private String nomAnalyse;
        private List<MedicamentInteractionDTO> medicamentsInteragissant;
        private List<SpecificiteInteractionDTO> specificitesInteragissantes;
    }

    @Data
    @Builder
    public static class MedicamentInteractionDTO {
        private UUID medicamentId;
        private String nomCommercial;
        private String dci;
        private String typeInteraction;
        private String niveauCriticite;
        private Integer delaiArret;
        private String recommandation;
    }

    @Data
    @Builder
    public static class SpecificiteInteractionDTO {
        private UUID specificiteId;
        private String titre;
        private String niveauAlerte;
        private String typeImpact; // CONTRE_INDICATION, MODIFICATION, PRECAUTION
        private String instruction;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/AnalyseResponseDTO.java

```java
package com.lims.referential.dto.response;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.enums.analyses.NiveauUrgence;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;


@Data
@Builder
public class AnalyseResponseDTO {

    private UUID id;
    private String codeNabm;
    private String libelle;
    private String libelleAbrege;
    private String description;
    private CategorieAnalyse categorie;
    private String sousCategorie;
    private String methodeTechnique;
    private String uniteResultat;
    private Analyse.ValeursNormales valeursNormales;
    private Analyse.DelaiRendu delaiRendu;
    private List<Analyse.TubeRequis> tubesRequis;
    private Analyse.ConditionsPreAnalytiques conditionsPreAnalytiques;
    private Analyse.Tarif tarif;
    private NiveauUrgence niveauUrgence;
    private List<String> analysesAssociees;
    private List<String> contraindicationsRelatives;
    private String observationsSpeciales;
    private Boolean actif;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}

```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/BulkOperationResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class BulkOperationResponseDTO {

    private String operation;
    private Integer totalRequested;
    private Integer successful;
    private Integer failed;
    private Integer skipped;
    private List<UUID> successfulIds;
    private Map<UUID, String> errors; // ID -> message d'erreur
    private LocalDateTime executedAt;
    private String summary;

    public static BulkOperationResponseDTO of(String operation, List<UUID> successful, Map<UUID, String> errors) {
        return BulkOperationResponseDTO.builder()
                .operation(operation)
                .totalRequested(successful.size() + errors.size())
                .successful(successful.size())
                .failed(errors.size())
                .skipped(0)
                .successfulIds(successful)
                .errors(errors)
                .executedAt(LocalDateTime.now())
                .summary(String.format("Opération %s: %d succès, %d échecs",
                        operation, successful.size(), errors.size()))
                .build();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/ErrorResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ErrorResponseDTO {

    private LocalDateTime timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
    private Map<String, List<String>> validationErrors;

    public static ErrorResponseDTO of(int status, String error, String message, String path) {
        return ErrorResponseDTO.builder()
                .timestamp(LocalDateTime.now())
                .status(status)
                .error(error)
                .message(message)
                .path(path)
                .build();
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/GeographiqueResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class GeographiqueResponseDTO {

    private UUID id;
    private String codePostal;
    private String nomCommune;
    private String codeCommune;

    // Hiérarchie administrative
    private String departement;
    private String codeDepartement;
    private String region;
    private String codeRegion;

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Informations démographiques
    private Integer population;
    private BigDecimal superficieKm2;
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    private List<String> laboratoiresZone;
    private BigDecimal distanceLaboratoirePlusProcheKm;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/LaboratoireResponseDTO.java

```java
package com.lims.referential.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@Schema(description = "Réponse contenant les informations d'un laboratoire")
public class LaboratoireResponseDTO {

    @Schema(description = "Identifiant unique du laboratoire")
    private String id;

    @Schema(description = "Nom du laboratoire")
    private String nom;

    @Schema(description = "Description du laboratoire")
    private String description;

    @Schema(description = "Adresse complète")
    private String adresse;

    @Schema(description = "Ville")
    private String ville;

    @Schema(description = "Code postal")
    private String codePostal;

    @Schema(description = "Pays")
    private String pays;

    @Schema(description = "Informations de contact")
    private ContactResponseDTO contact;

    @Schema(description = "Informations pratiques")
    private InformationsPratiquesResponseDTO informationsPratiques;

    @Schema(description = "Capacités techniques")
    private CapacitesTechniquesResponseDTO capacitesTechniques;

    @Schema(description = "Statut actif du laboratoire")
    private Boolean actif;

    @Schema(description = "Date de création")
    private LocalDateTime dateCreation;

    @Schema(description = "Date de modification")
    private LocalDateTime dateModification;

    @Schema(description = "Créé par")
    private String creePar;

    @Schema(description = "Modifié par")
    private String modifiePar;

    // ============================================
    // DTOs DE RÉPONSE IMBRIQUÉS
    // ============================================

    @Data
    @Builder
    public static class ContactResponseDTO {
        private String telephone;
        private String fax;
        private String email;
        private String siteWeb;
    }

    @Data
    @Builder
    public static class InformationsPratiquesResponseDTO {
        private String horairesOuverture;
        private Boolean parkingDisponible;
        private Boolean accesHandicapes;
        private String transportPublic;
    }

    @Data
    @Builder
    public static class CapacitesTechniquesResponseDTO {
        private List<String> analysesDisponibles;
        private List<String> specialitesTechniques;
        private List<String> equipementsSpeciaux;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/MedecinResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedecinResponseDTO {

    private UUID id;
    private String numeroRpps;
    private String nom;
    private String prenom;
    private String titre;
    private String specialitePrincipale;
    private List<String> specialitesSecondaires;

    // Adresse professionnelle
    private AdresseResponseDTO adresse;

    // Contact professionnel
    private ContactResponseDTO contact;

    private String modeExercice;
    private Integer secteurConventionnel;
    private LocalDate dateInstallation;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;

    @Data
    @Builder
    public static class AdresseResponseDTO {
        private String ligne1;
        private String ligne2;
        private String codePostal;
        private String ville;
        private String departement;
        private String region;
        private String pays;
    }

    @Data
    @Builder
    public static class ContactResponseDTO {
        private String telephone;
        private String fax;
        private String email;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/MedicamentResponse.java

```java
package com.lims.referential.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * DTO de réponse pour un médicament
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Réponse contenant les informations d'un médicament")
public class MedicamentResponse {

    @Schema(description = "Identifiant unique du médicament", example = "123e4567-e89b-12d3-a456-426614174000")
    private String id;

    @Schema(description = "Code CIS du médicament", example = "CIS12345678")
    private String codeCis;

    @Schema(description = "Dénomination du médicament", example = "DOLIPRANE 500 mg, comprimé")
    private String denomination;

    @Schema(description = "Forme pharmaceutique", example = "comprimé")
    private String formePharma;

    @Schema(description = "Voies d'administration", example = "orale")
    private String voiesAdmin;

    @Schema(description = "Statut AMM", example = "Autorisation active")
    private String statutAmm;

    @Schema(description = "Type de procédure AMM", example = "Procédure nationale")
    private String typeProcedure;

    @Schema(description = "Laboratoire titulaire", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireTitulaire;

    @Schema(description = "Laboratoire exploitant", example = "SANOFI AVENTIS FRANCE")
    private String laboratoireExploitant;

    @Schema(description = "Date AMM", example = "1985-07-25T00:00:00")
    private LocalDateTime dateAmm;

    @Schema(description = "Statut BdM (Base de données publique des médicaments)", example = "Commercialisé")
    private String statutBdm;

    @Schema(description = "Numéro autorisation européenne", example = "EU/1/15/1234/001")
    private String numeroAutorisationEuropeenne;

    @Schema(description = "Titulaires AMM", example = "SANOFI AVENTIS FRANCE")
    private String titulairesAmm;

    @Schema(description = "Surveillance renforcée", example = "false")
    private Boolean surveillanceRenforcee;

    @Schema(description = "Prix de vente public", example = "2.18")
    private BigDecimal prixVente;

    @Schema(description = "Taux de remboursement", example = "65")
    private Integer tauxRemboursement;

    @Schema(description = "Indique si le médicament est actif", example = "true")
    private Boolean actif;

    @Schema(description = "Date de création de l'enregistrement")
    private LocalDateTime dateCreation;

    @Schema(description = "Date de dernière modification")
    private LocalDateTime dateModification;

    @Schema(description = "Utilisateur ayant créé l'enregistrement")
    private String creePar;

    @Schema(description = "Utilisateur ayant modifié l'enregistrement")
    private String modifiePar;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/MedicamentResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class MedicamentResponseDTO {

    private UUID id;
    private String nomCommercial;
    private String dci;
    private String codeCip;

    // Classification
    private String classeTherapeutique;
    private String sousClasse;
    private String formePharmaceutique;
    private String dosage;
    private String voieAdministration;

    // Interactions avec analyses
    private List<String> analysesImpactees;
    private String typeInteraction;
    private String niveauCriticite;

    // Délais pré-analytiques
    private Boolean arretRequis;
    private Integer delaiArretHeures;
    private String instructionsArret;

    // Informations complémentaires
    private String principeActif;
    private String laboratoireFabricant;
    private String statutCommercialisation;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/MutuelleResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
public class MutuelleResponseDTO {

    private UUID id;
    private String nom;
    private String nomCommercial;
    private String siret;

    // Classification
    private String typeOrganisme;
    private String codeOrganisme;
    private String regimeRattachement;

    // Coordonnées
    private AdresseMutuelleResponseDTO adresse;

    // Contact
    private ContactMutuelleResponseDTO contact;

    // Informations de prise en charge
    private PriseEnChargeResponseDTO priseEnCharge;

    // Facturation
    private FacturationResponseDTO facturation;

    // Conventions spéciales
    private List<String> conventionsSpeciales;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;

    @Data
    @Builder
    public static class AdresseMutuelleResponseDTO {
        private String ligne1;
        private String ligne2;
        private String codePostal;
        private String ville;
        private String departement;
        private String region;
    }

    @Data
    @Builder
    public static class ContactMutuelleResponseDTO {
        private String telephone;
        private String fax;
        private String email;
        private String siteWeb;
    }

    @Data
    @Builder
    public static class PriseEnChargeResponseDTO {
        private BigDecimal tauxBaseRemboursement;
        private BigDecimal plafondAnnuelEuro;
        private BigDecimal franchiseEuro;
        private List<AnalyseCouvertureResponseDTO> analysesCouvertes;
        private List<String> analysesExclues;
    }

    @Data
    @Builder
    public static class FacturationResponseDTO {
        private Map<String, Object> codesFacturation;
        private Integer delaiPaiementJours;
        private String modeTransmission;
    }

    @Data
    @Builder
    public static class AnalyseCouvertureResponseDTO {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/PagedResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.domain.Page;

import java.util.List;

@Data
@Builder
public class PagedResponseDTO<T> {

    private List<T> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private boolean first;
    private boolean last;
    private boolean empty;

    public static <T> PagedResponseDTO<T> from(Page<T> page) {
        return PagedResponseDTO.<T>builder()
                .content(page.getContent())
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .first(page.isFirst())
                .last(page.isLast())
                .empty(page.isEmpty())
                .build();
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/PatientSpecificityResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class PatientSpecificityResponseDTO {

    private UUID id;
    private String titre;
    private String description;
    private String categoryId;

    // Catégorie associée
    private SpecificityCategoryResponseDTO category;

    // Niveau d'alerte
    private String niveauAlerte;
    private String icone;

    // Mots-clés pour recherche
    private List<String> motsCles;

    // Instructions associées
    private String instructionsPreleveur;
    private String instructionsTechnique;
    private String instructionsAdministrative;

    // Contraintes pré-analytiques
    private List<String> impactPrelevements;
    private List<String> analysesContreIndiquees;
    private List<String> analysesModifiees;

    // Priorité et temps
    private Integer prioritePreleveur;
    private Integer tempsSupplementaireMinutes;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/SpecificityCategoryResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class SpecificityCategoryResponseDTO {

    private String id;
    private String nom;
    private String description;
    private String couleur;
    private String icone;
    private Integer ordreAffichage;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Spécificités associées (optionnel)
    private List<PatientSpecificityResponseDTO> specificities;
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/SynchronisationResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class SynchronisationResponseDTO {

    private String syncId;
    private List<String> domaines;
    private String modeSync;
    private String statut; // EN_COURS, TERMINE, ERREUR
    private LocalDateTime dateDebut;
    private LocalDateTime dateFin;
    private Map<String, SyncResultatDTO> resultatsParDomaine;
    private List<String> erreurs;
    private String message;

    @Data
    @Builder
    public static class SyncResultatDTO {
        private String domaine;
        private Integer totalTraite;
        private Integer ajoutes;
        private Integer modifies;
        private Integer supprimes;
        private Integer erreurs;
        private List<String> detailsErreurs;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/dto/response/TourneeOptimisationResponseDTO.java

```java
package com.lims.referential.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

@Data
@Builder
public class TourneeOptimisationResponseDTO {

    private List<EtapeResponseDTO> etapesOptimisees;
    private BigDecimal distanceTotaleKm;
    private Integer dureeVisitesTotaleMinutes;
    private Integer dureeTrajetTotaleMinutes;
    private LocalTime heureDepart;
    private LocalTime heureRetourEstimee;
    private String critereOptimisation;
    private LocalDateTime calculeLe;

    @Data
    @Builder
    public static class EtapeResponseDTO {
        private Integer ordre;
        private BigDecimal latitude;
        private BigDecimal longitude;
        private String adresse;
        private LocalTime heureArriveeEstimee;
        private Integer dureeVisite;
        private BigDecimal distanceDepuisPrecedent;
        private String commentaire;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Analyse.java

```java
// Analyse.java
package com.lims.referential.entity;

import com.lims.referential.enums.analyses.TemperatureConservation;
import com.lims.referential.enums.analyses.*;
import com.lims.referential.enums.common.UniteTemps;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * Entité représentant une analyse biologique avec code NABM
 */
@Entity
@Table(name = "analyses", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Analyse extends BaseEntity {

    @Column(name = "code_nabm", unique = true, nullable = false, length = 10)
    @NotBlank(message = "Le code NABM est obligatoire")
    @Size(max = 10, message = "Le code NABM ne peut pas dépasser 10 caractères")
    private String codeNabm;

    @Column(name = "libelle", nullable = false)
    @NotBlank(message = "Le libellé est obligatoire")
    @Size(max = 255, message = "Le libellé ne peut pas dépasser 255 caractères")
    private String libelle;

    @Column(name = "libelle_abrege", length = 50)
    @Size(max = 50, message = "Le libellé abrégé ne peut pas dépasser 50 caractères")
    private String libelleAbrege;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "categorie", length = 100)
    @Enumerated(EnumType.STRING)
    private CategorieAnalyse categorie;

    @Column(name = "sous_categorie", length = 100)
    private String sousCategorie;

    @Column(name = "methode_technique", length = 100)
    private String methodeTechnique;

    @Column(name = "unite_resultat", length = 20)
    private String uniteResultat;

    // Valeurs normales stockées en JSON
    @Column(name = "valeurs_normales", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ValeursNormales valeursNormales;

    // Délai de rendu
    @Column(name = "delai_rendu", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private DelaiRendu delaiRendu;

    // Tubes requis stockés en JSON
    @Column(name = "tubes_requis", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<TubeRequis> tubesRequis;

    // Conditions pré-analytiques
    @Column(name = "conditions_pre_analytiques", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ConditionsPreAnalytiques conditionsPreAnalytiques;

    // Tarification
    @Column(name = "tarif", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Tarif tarif;

    @Column(name = "niveau_urgence")
    @Enumerated(EnumType.STRING)
    private NiveauUrgence niveauUrgence;

    // Analyses associées (codes NABM)
    @Column(name = "analyses_associees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesAssociees;

    @Column(name = "contrindications_relatives", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> contraindicationsRelatives;

    @Column(name = "observations_speciales", columnDefinition = "TEXT")
    private String observationsSpeciales;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classes internes pour les structures JSON
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValeursNormales {
        private BigDecimal min;
        private BigDecimal max;
        private String unite;
        private String commentaire;
        private Map<String, Object> valeursParAge;
        private Map<String, Object> valeursParSexe;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DelaiRendu {
        private Integer valeur;
        private UniteTemps unite;
        private Integer valeurUrgent;
        private UniteTemps uniteUrgent;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TubeRequis {
        private TypeTube type;
        private BigDecimal volume;
        private CouleurTube couleur;
        private Boolean obligatoire;
        private String commentaire;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConditionsPreAnalytiques {
        private Boolean jeune;
        private Integer dureeJeune;
        private PositionPatient positionPatient;
        private List<String> medicamentsArreter;
        private String instructionsSpeciales;
        private Integer delaiStabilite;
        private TemperatureConservation temperatureConservation;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Tarif {
        private BigDecimal prixPublic;
        private Integer coefficientB;
        private Boolean remboursementSecu;
        private Integer tauxRemboursement;
        private BigDecimal prixConventionne;
    }
}


```

# lims-ref-service/src/main/java/com/lims/referential/entity/BaseEntity.java

```java
// BaseEntity.java
package com.lims.referential.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité de base avec audit automatique
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @Version
    @Column(name = "version")
    private Integer version;

    /**
     * Marque l'entité comme supprimée (soft delete)
     */
    public void markAsDeleted() {
        this.deletedAt = LocalDateTime.now();
    }

    /**
     * Restaure l'entité supprimée
     */
    public void restore() {
        this.deletedAt = null;
    }

    /**
     * Vérifie si l'entité est supprimée
     */
    public boolean isDeleted() {
        return deletedAt != null;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Geographique.java

```java
package com.lims.referential.entity;

import com.lims.referential.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name = "geographique", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Geographique extends BaseEntity {

    @Column(name = "code_postal", nullable = false, length = 10)
    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10)
    private String codePostal;

    @Column(name = "nom_commune", nullable = false)
    @NotBlank(message = "Le nom de la commune est obligatoire")
    @Size(max = 255)
    private String nomCommune;

    @Column(name = "code_commune", length = 10)
    @Size(max = 10)
    private String codeCommune;

    // Hiérarchie administrative
    @Column(name = "departement", nullable = false, length = 100)
    @NotBlank(message = "Le département est obligatoire")
    @Size(max = 100)
    private String departement;

    @Column(name = "code_departement", nullable = false, length = 3)
    @NotBlank(message = "Le code département est obligatoire")
    @Size(max = 3)
    private String codeDepartement;

    @Column(name = "region", nullable = false, length = 100)
    @NotBlank(message = "La région est obligatoire")
    @Size(max = 100)
    private String region;

    @Column(name = "code_region", nullable = false, length = 3)
    @NotBlank(message = "Le code région est obligatoire")
    @Size(max = 3)
    private String codeRegion;

    // Géolocalisation
    @Column(name = "latitude", precision = 10, scale = 8)
    private BigDecimal latitude;

    @Column(name = "longitude", precision = 11, scale = 8)
    private BigDecimal longitude;

    // Informations démographiques
    @Column(name = "population")
    private Integer population;

    @Column(name = "superficie_km2", precision = 8, scale = 2)
    private BigDecimal superficieKm2;

    @Column(name = "densite_hab_km2", precision = 8, scale = 2)
    private BigDecimal densiteHabKm2;

    // Zone de desserte laboratoires
    @Column(name = "laboratoires_zone", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> laboratoiresZone; // Array des IDs laboratoires

    @Column(name = "distance_laboratoire_plus_proche_km", precision = 6, scale = 2)
    private BigDecimal distanceLaboratoirePlusProcheKm;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Laboratoire.java

```java
package com.lims.referential.entity;

import com.lims.referential.enums.laboratoires.SpecialiteTechnique;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Entité représentant un laboratoire d'analyses médicales.
 */
@Entity
@Table(name = "laboratoires", schema = "lims_referential")
@EntityListeners(AuditingEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(exclude = {"dateCreation", "dateModification"})
public class Laboratoire {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    private UUID id;

    @Column(name = "nom", nullable = false, length = 255)
    private String nom;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "adresse", nullable = false, length = 500)
    private String adresse;

    @Column(name = "ville", nullable = false, length = 100)
    private String ville;

    @Column(name = "code_postal", nullable = false, length = 10)
    private String codePostal;

    @Column(name = "pays", length = 100)
    private String pays;

    // ============================================
    // INFORMATIONS DE CONTACT
    // ============================================

    @Column(name = "telephone", length = 20)
    private String telephone;

    @Column(name = "fax", length = 20)
    private String fax;

    @Column(name = "email", length = 255)
    private String email;

    @Column(name = "site_web", length = 255)
    private String siteWeb;

    // ============================================
    // INFORMATIONS PRATIQUES
    // ============================================

    @Column(name = "horaires_ouverture", length = 500)
    private String horairesOuverture;

    @Column(name = "parking_disponible")
    @Builder.Default
    private Boolean parkingDisponible = false;

    @Column(name = "acces_handicapes")
    @Builder.Default
    private Boolean accesHandicapes = false;

    @Column(name = "transport_public", length = 255)
    private String transportPublic;

    // ============================================
    // CAPACITÉS TECHNIQUES (stockées en JSON ou liste séparées par virgules)
    // ============================================
    @Column(name = "analyses_disponibles", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesDisponibles;

    @Column(name = "specialites_techniques", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<SpecialiteTechnique> specialitesTechniques;

    @Column(name = "equipements_speciaux", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> equipementsSpeciaux;

    // ============================================
    // STATUT ET AUDIT
    // ============================================

    @Column(name = "actif", nullable = false)
    @Builder.Default
    private Boolean actif = true;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @CreatedBy
    @Column(name = "cree_par", length = 100, updatable = false)
    private String creePar;

    @LastModifiedBy
    @Column(name = "modifie_par", length = 100)
    private String modifiePar;

    @Version
    @Column(name = "version")
    private Long version;

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Désactive le laboratoire (soft delete)
     */
    public void desactiver() {
        this.actif = false;
    }

    /**
     * Réactive le laboratoire
     */
    public void reactiver() {
        this.actif = true;
    }

    /**
     * Marque le laboratoire comme supprimé (soft delete)
     */
    public void markAsDeleted() {
        this.deletedAt = LocalDateTime.now();
        this.actif = false;
    }

    /**
     * Vérifie si le laboratoire est supprimé
     */
    public boolean isDeleted() {
        return this.deletedAt != null;
    }

    /**
     * Restaure un laboratoire supprimé
     */
    public void restore() {
        this.deletedAt = null;
        this.actif = true;
    }

    /**
     * Vérifie si le laboratoire a un contact email
     */
    public boolean hasEmail() {
        return this.email != null && !this.email.trim().isEmpty();
    }

    /**
     * Vérifie si le laboratoire propose une analyse spécifique
     */
    public boolean proposeAnalyse(String codeAnalyse) {
        return this.analysesDisponibles != null &&
                this.analysesDisponibles.contains(codeAnalyse);
    }

    // ============================================
    // CALLBACKS JPA
    // ============================================

    @PrePersist
    protected void onCreate() {
        if (this.actif == null) {
            this.actif = true;
        }
        if (this.parkingDisponible == null) {
            this.parkingDisponible = false;
        }
        if (this.accesHandicapes == null) {
            this.accesHandicapes = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        // Validation métier avant mise à jour
        if (this.email != null) {
            this.email = this.email.toLowerCase().trim();
        }
    }

    /**
     * Requête personnalisée pour exclure les éléments supprimés
     */
    @PreRemove
    protected void onRemove() {
        // Au lieu de supprimer physiquement, marquer comme supprimé
        markAsDeleted();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Medecin.java

```java
// Medecin.java
package com.lims.referential.entity;

import com.lims.referential.enums.analyses.Civilite;
import com.lims.referential.enums.medecins.SecteurConventionnement;
import com.lims.referential.enums.medecins.SpecialiteMedicale;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.Map;

/**
 * Entité représentant un médecin avec numéro RPPS
 */
@Entity
@Table(name = "medecins", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Medecin extends BaseEntity {

    @Column(name = "numero_rpps", unique = true, nullable = false, length = 11)
    @NotBlank(message = "Le numéro RPPS est obligatoire")
    @Pattern(regexp = "\\d{11}", message = "Le numéro RPPS doit contenir exactement 11 chiffres")
    private String numeroRpps;

    @Column(name = "civilite", length = 20)
    @Enumerated(EnumType.STRING)
    private Civilite civilite;

    @Column(name = "nom", nullable = false, length = 100)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 100, message = "Le nom ne peut pas dépasser 100 caractères")
    private String nom;

    @Column(name = "prenom", nullable = false, length = 100)
    @NotBlank(message = "Le prénom est obligatoire")
    @Size(max = 100, message = "Le prénom ne peut pas dépasser 100 caractères")
    private String prenom;

    @Column(name = "specialite_principale", length = 100)
    @Enumerated(EnumType.STRING)
    private SpecialiteMedicale specialitePrincipale;

    @Column(name = "specialites_secondaires", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<SpecialiteMedicale> specialitesSecondaires;

    // Adresse professionnelle
    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "ligne1", column = @Column(name = "adresse_ligne1")),
            @AttributeOverride(name = "ligne2", column = @Column(name = "adresse_ligne2")),
            @AttributeOverride(name = "codePostal", column = @Column(name = "code_postal")),
            @AttributeOverride(name = "ville", column = @Column(name = "ville")),
            @AttributeOverride(name = "departement", column = @Column(name = "departement")),
            @AttributeOverride(name = "region", column = @Column(name = "region")),
            @AttributeOverride(name = "pays", column = @Column(name = "pays"))
    })
    private Adresse adresse;

    // Contact professionnel
    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "telephone", column = @Column(name = "telephone")),
            @AttributeOverride(name = "fax", column = @Column(name = "fax")),
            @AttributeOverride(name = "email", column = @Column(name = "email"))
    })
    private Contact contact;

    @Column(name = "secteur_conventionnement")
    @Enumerated(EnumType.STRING)
    private SecteurConventionnement secteurConventionnement;

    @Builder.Default
    @Column(name = "conventionne_secu")
    private Boolean conventionneSecu = true;

    @Builder.Default
    @Column(name = "carte_vitale")
    private Boolean cartevitale = true;

    @Builder.Default
    @Column(name = "rdv_en_ligne")
    private Boolean rdvEnLigne = false;

    @Column(name = "horaires_consultation", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, List<String>> horairesConsultation;

    @Column(name = "observations_speciales", columnDefinition = "TEXT")
    private String observationsSpeciales;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classes internes
    @Embeddable
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Adresse {
        @Size(max = 255)
        private String ligne1;

        @Size(max = 255)
        private String ligne2;

        @Size(max = 10)
        @Pattern(regexp = "\\d{5}", message = "Le code postal doit contenir 5 chiffres")
        private String codePostal;

        @Size(max = 100)
        private String ville;

        @Size(max = 100)
        private String departement;

        @Size(max = 100)
        private String region;

        @Builder.Default
        @Size(max = 50)
        private String pays = "France";
    }

    @Embeddable
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Contact {
        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de téléphone invalide")
        private String telephone;

        @Pattern(regexp = "^[0-9+\\-\\s()]{8,20}$", message = "Format de fax invalide")
        private String fax;

        @Email(message = "Format d'email invalide")
        @Size(max = 255)
        private String email;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Medicament.java

```java
// lims-ref-service/src/main/java/com/lims/referential/entity/Medicament.java
package com.lims.referential.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entité représentant un médicament dans la base de données publique des médicaments.
 * Basée sur les données de l'ANSM (Agence nationale de sécurité du médicament).
 */
@Entity
@Table(name = "medicaments", schema = "lims_referential")
@EntityListeners(AuditingEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(exclude = {"dateCreation", "dateModification"})
public class Medicament {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    private UUID id;

    /**
     * Code CIS (Code Identifiant de Spécialité)
     * Identifiant unique du médicament selon l'ANSM
     */
    @Column(name = "code_cis", nullable = false, unique = true, length = 50)
    private String codeCis;

    /**
     * Dénomination du médicament
     */
    @Column(name = "denomination", nullable = false, length = 500)
    private String denomination;

    /**
     * Forme pharmaceutique (comprimé, gélule, sirop, etc.)
     */
    @Column(name = "forme_pharma", length = 200)
    private String formePharma;

    /**
     * Voies d'administration (orale, injectable, etc.)
     */
    @Column(name = "voies_admin", length = 200)
    private String voiesAdmin;

    /**
     * Statut de l'Autorisation de Mise sur le Marché
     */
    @Column(name = "statut_amm", length = 100)
    private String statutAmm;

    /**
     * Type de procédure d'autorisation
     */
    @Column(name = "type_procedure", length = 100)
    private String typeProcedure;

    /**
     * Laboratoire titulaire de l'AMM
     */
    @Column(name = "laboratoire_titulaire", length = 300)
    private String laboratoireTitulaire;

    /**
     * Laboratoire exploitant le médicament
     */
    @Column(name = "laboratoire_exploitant", length = 300)
    private String laboratoireExploitant;

    /**
     * Date d'obtention de l'AMM
     */
    @Column(name = "date_amm")
    private LocalDateTime dateAmm;

    /**
     * Statut dans la Base de données publique des médicaments
     */
    @Column(name = "statut_bdm", length = 100)
    private String statutBdm;

    /**
     * Numéro d'autorisation européenne (si applicable)
     */
    @Column(name = "numero_autorisation_europeenne", length = 100)
    private String numeroAutorisationEuropeenne;

    /**
     * Liste des titulaires de l'AMM
     */
    @Column(name = "titulaires_amm", length = 500)
    private String titulairesAmm;

    /**
     * Indique si le médicament fait l'objet d'une surveillance renforcée
     */
    @Column(name = "surveillance_renforcee")
    @Builder.Default
    private Boolean surveillanceRenforcee = false;

    /**
     * Prix de vente public (en euros)
     */
    @Column(name = "prix_vente", precision = 10, scale = 2)
    private BigDecimal prixVente;

    /**
     * Taux de remboursement par la Sécurité sociale (en pourcentage)
     */
    @Column(name = "taux_remboursement")
    private Integer tauxRemboursement;

    /**
     * Indique si le médicament est actif/visible dans le système
     */
    @Column(name = "actif", nullable = false)
    @Builder.Default
    private Boolean actif = true;

    // ============================================
    // CHAMPS D'AUDIT AUTOMATIQUES
    // ============================================

    @CreatedDate
    @Column(name = "date_creation", nullable = false, updatable = false)
    private LocalDateTime dateCreation;

    @LastModifiedDate
    @Column(name = "date_modification")
    private LocalDateTime dateModification;

    @CreatedBy
    @Column(name = "cree_par", length = 100, updatable = false)
    private String creePar;

    @LastModifiedBy
    @Column(name = "modifie_par", length = 100)
    private String modifiePar;

    /**
     * Version pour l'optimistic locking
     */
    @Version
    @Column(name = "version")
    private Long version;

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Désactive le médicament (soft delete)
     */
    public void desactiver() {
        this.actif = false;
    }

    /**
     * Réactive le médicament
     */
    public void reactiver() {
        this.actif = true;
    }

    /**
     * Vérifie si le médicament est remboursé
     */
    public boolean estRembourse() {
        return this.tauxRemboursement != null && this.tauxRemboursement > 0;
    }

    /**
     * Vérifie si le médicament est sous surveillance renforcée
     */
    public boolean estSousSurveillance() {
        return Boolean.TRUE.equals(this.surveillanceRenforcee);
    }

    // ============================================
    // CALLBACKS JPA
    // ============================================

    @PrePersist
    protected void onCreate() {
        if (this.actif == null) {
            this.actif = true;
        }
        if (this.surveillanceRenforcee == null) {
            this.surveillanceRenforcee = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        // Validation métier avant mise à jour
        if (this.codeCis != null) {
            this.codeCis = this.codeCis.toUpperCase().trim();
        }
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/Mutuelle.java

```java
package com.lims.referential.entity;

import com.lims.referential.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "mutuelles", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Mutuelle extends BaseEntity {

    @Column(name = "nom", nullable = false)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255)
    private String nom;

    @Column(name = "nom_commercial")
    @Size(max = 255)
    private String nomCommercial;

    @Column(name = "siret", length = 14)
    @Size(max = 14)
    private String siret;

    // Classification
    @Column(name = "type_organisme", length = 50)
    @Size(max = 50)
    private String typeOrganisme; // cpam, mutuelle, assurance, cmuc

    @Column(name = "code_organisme", length = 20)
    @Size(max = 20)
    private String codeOrganisme;

    @Column(name = "regime_rattachement", length = 100)
    @Size(max = 100)
    private String regimeRattachement;

    // Coordonnées
    @Column(name = "adresse_ligne1")
    @Size(max = 255)
    private String adresseLigne1;

    @Column(name = "adresse_ligne2")
    @Size(max = 255)
    private String adresseLigne2;

    @Column(name = "code_postal", length = 10)
    @Size(max = 10)
    private String codePostal;

    @Column(name = "ville", length = 100)
    @Size(max = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    @Size(max = 100)
    private String departement;

    @Column(name = "region", length = 100)
    @Size(max = 100)
    private String region;

    // Contact
    @Column(name = "telephone", length = 20)
    private String telephone;

    @Column(name = "fax", length = 20)
    private String fax;

    @Column(name = "email")
    @Size(max = 255)
    private String email;

    @Column(name = "site_web")
    @Size(max = 255)
    private String siteWeb;

    // Informations de prise en charge
    @Builder.Default
    @Column(name = "taux_base_remboursement", precision = 5, scale = 2)
    private BigDecimal tauxBaseRemboursement = new BigDecimal("70.00");

    @Column(name = "plafond_annuel_euro", precision = 10, scale = 2)
    private BigDecimal plafondAnnuelEuro;

    @Builder.Default
    @Column(name = "franchise_euro", precision = 6, scale = 2)
    private BigDecimal franchiseEuro = BigDecimal.ZERO;

    // Analyses couvertes
    @Column(name = "analyses_couvertes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<AnalyseCouverture> analysesCouvertes;

    @Column(name = "analyses_exclues", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesExclues;

    // Facturation
    @Column(name = "codes_facturation", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> codesFacturation;

    @Builder.Default
    @Column(name = "delai_paiement_jours")
    private Integer delaiPaiementJours = 30;

    @Column(name = "mode_transmission", length = 50)
    @Size(max = 50)
    private String modeTransmission; // noemie, edifact, papier

    // Conventions spéciales
    @Column(name = "conventions_speciales", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> conventionsSpeciales;

    // Ajout du champ tiersPayant manquant
    @Column(name = "tiers_payant")
    private Boolean tiersPayant;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    // Classe interne pour les analyses couvertes
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AnalyseCouverture {
        private String codeNabm;
        private BigDecimal tauxRemboursement;
        private BigDecimal plafond;
        private String conditions;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/PatientSpecificity.java

```java
package com.lims.referential.entity;

import com.lims.referential.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Where;
import org.hibernate.type.SqlTypes;

import java.util.List;

@Entity
@Table(name = "patient_specificities", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class PatientSpecificity extends BaseEntity {

    @Column(name = "titre", nullable = false)
    @NotBlank(message = "Le titre est obligatoire")
    @Size(max = 255)
    private String titre;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "category_id", length = 50)
    @Size(max = 50)
    private String categoryId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", insertable = false, updatable = false)
    private SpecificityCategory category;

    // Niveau d'alerte
    @Column(name = "niveau_alerte", nullable = false, length = 20)
    @NotBlank(message = "Le niveau d'alerte est obligatoire")
    @Size(max = 20)
    private String niveauAlerte; // normal, warning, critical

    @Column(name = "icone", length = 50)
    @Size(max = 50)
    private String icone;

    // Mots-clés pour recherche
    @Column(name = "mots_cles", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> motsCles;

    // Instructions associées
    @Column(name = "instructions_preleveur", columnDefinition = "TEXT")
    private String instructionsPreleveur;

    @Column(name = "instructions_technique", columnDefinition = "TEXT")
    private String instructionsTechnique;

    @Column(name = "instructions_administrative", columnDefinition = "TEXT")
    private String instructionsAdministrative;

    // Contraintes pré-analytiques
    @Column(name = "impact_prelevements", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> impactPrelevements;

    @Column(name = "analyses_contre_indiquees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesContreIndiquees;

    @Column(name = "analyses_modifiees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesModifiees;

    // Priorité et temps
    @Builder.Default
    @Column(name = "priorite_preleveur")
    private Integer prioritePreleveur = 1; // 1=normale, 2=prioritaire, 3=urgente

    @Builder.Default
    @Column(name = "temps_supplementaire_minutes")
    private Integer tempsSupplementaireMinutes = 0;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}
```

# lims-ref-service/src/main/java/com/lims/referential/entity/SpecificityCategory.java

```java
package com.lims.referential.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "specificity_categories", schema = "lims_referential")
@EntityListeners(AuditingEntityListener.class)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class SpecificityCategory {

    @Id
    @Column(name = "id", length = 50)
    private String id;

    @Column(name = "nom", nullable = false)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255)
    private String nom;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "couleur", length = 7)
    @Size(max = 7)
    private String couleur; // Code couleur hex

    @Column(name = "icone", length = 50)
    @Size(max = 50)
    private String icone;

    @Builder.Default
    @Column(name = "ordre_affichage")
    private Integer ordreAffichage = 0;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "category", fetch = FetchType.LAZY)
    private List<PatientSpecificity> specificities;
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/CategorieAnalyse.java

```java
package com.lims.referential.enums.analyses;

public enum CategorieAnalyse {
    BIOCHIMIE,
    HEMATOLOGIE,
    MICROBIOLOGIE,
    IMMUNOLOGIE,
    PARASITOLOGIE,
    ANATOMIE_PATHOLOGIQUE,
    GENETIQUE,
    TOXICOLOGIE,
    ENDOCRINOLOGIE,
    ALLERGOLOGIE
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/Civilite.java

```java
package com.lims.referential.enums.analyses;

public enum Civilite {
    DR("Docteur"),
    PR("Professeur"),
    M("Monsieur"),
    MME("Madame");

    private final String libelle;

    Civilite(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/CouleurTube.java

```java
package com.lims.referential.enums.analyses;

public enum CouleurTube {
    ROUGE,
    VIOLET,
    VERT,
    BLEU,
    JAUNE,
    GRIS,
    NOIR,
    BLANC
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/NiveauUrgence.java

```java
package com.lims.referential.enums.analyses;

public enum NiveauUrgence {
    NORMAL,
    PRIORITAIRE,
    URGENT,
    VITAL
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/PositionPatient.java

```java
package com.lims.referential.enums.analyses;

public enum PositionPatient {
    DEBOUT,
    ASSIS,
    ALLONGE,
    INDIFFERENT
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/TemperatureConservation.java

```java
package com.lims.referential.enums.analyses;

public enum TemperatureConservation {
    TEMPERATURE_AMBIANTE,
    REFRIGERE_2_8,
    CONGELE_MOINS_20,
    CONGELE_MOINS_80
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/analyses/TypeTube.java

```java
package com.lims.referential.enums.analyses;

public enum TypeTube {
    SERUM,
    PLASMA_EDTA,
    PLASMA_HEPARINE,
    PLASMA_CITRATE,
    SANG_TOTAL,
    URINE,
    SELLES,
    AUTRE
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/common/UniteTemps.java

```java
package com.lims.referential.enums.common;

public enum UniteTemps {
    MINUTES("Minutes"),
    HEURES("Heures"),
    JOURS("Jours"),
    SEMAINES("Semaines"),
    MOIS("Mois"),
    ANNEES("Années");

    private final String libelle;

    UniteTemps(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/laboratoires/SpecialiteTechnique.java

```java
package com.lims.referential.enums.laboratoires;

public enum SpecialiteTechnique {
    BIOCHIMIE("Biochimie"),
    HEMATOLOGIE("Hématologie"),
    MICROBIOLOGIE("Microbiologie"),
    IMMUNOLOGIE("Immunologie"),
    GENETIQUE("Génétique"),
    ANATOMIE_PATHOLOGIQUE("Anatomie pathologique"),
    TOXICOLOGIE("Toxicologie"),
    RADIOLOGIE("Radiologie"),
    ECHOGRAPHIE("Échographie"),
    ENDOSCOPIE("Endoscopie"),
    CARDIOLOGIE("Cardiologie"),
    PNEUMOLOGIE("Pneumologie"),
    NEUROLOGIE("Neurologie");

    private final String libelle;

    SpecialiteTechnique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/laboratoires/TypeLaboratoire.java

```java
package com.lims.referential.enums.laboratoires;

public enum TypeLaboratoire {
    PRIVE("Laboratoire privé"),
    HOSPITALIER("Laboratoire hospitalier"),
    UNIVERSITAIRE("Laboratoire universitaire"),
    RECHERCHE("Laboratoire de recherche"),
    VETERINAIRE("Laboratoire vétérinaire"),
    INDUSTRIEL("Laboratoire industriel"),
    AUTRE("Autre");

    private final String libelle;

    TypeLaboratoire(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medecins/ModeExercice.java

```java
package com.lims.referential.enums.medecins;

public enum ModeExercice {
    LIBERAL("Libéral"),
    SALARIE("Salarié"),
    MIXTE("Mixte"),
    FONCTIONNAIRE("Fonctionnaire"),
    REMPLACANT("Remplaçant");

    private final String libelle;

    ModeExercice(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/medecins/SecteurConventionnement.java

```java
package com.lims.referential.enums.medecins;

public enum SecteurConventionnement {
    SECTEUR_1("Secteur 1 - Tarifs conventionnés"),
    SECTEUR_2("Secteur 2 - Dépassements d'honoraires autorisés"),
    SECTEUR_3("Secteur 3 - Non conventionné"),
    NON_CONVENTIONNE("Non conventionné");

    private final String description;

    SecteurConventionnement(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/medecins/SpecialiteMedicale.java

```java
package com.lims.referential.enums.medecins;

public enum SpecialiteMedicale {
    MEDECINE_GENERALE("Médecine générale"),
    CARDIOLOGIE("Cardiologie"),
    DERMATOLOGIE("Dermatologie"),
    ENDOCRINOLOGIE("Endocrinologie"),
    GASTROENTEROLOGIE("Gastro-entérologie"),
    GERIATRIE("Gériatrie"),
    GYNECOLOGIE("Gynécologie"),
    HEMATOLOGIE("Hématologie"),
    NEUROLOGIE("Neurologie"),
    ONCOLOGIE("Oncologie"),
    PEDIATRIE("Pédiatrie"),
    PSYCHIATRIE("Psychiatrie"),
    RADIOLOGIE("Radiologie"),
    UROLOGIE("Urologie"),
    DIABETOLOGIE("Diabétologie"),
    NEPHROLOGIE("Néphrologie"),
    PNEUMOLOGIE("Pneumologie"),
    RHUMATOLOGIE("Rhumatologie"),
    INFECTIOLOGIE("Infectiologie"),
    AUTRE("Autre");

    private final String libelle;

    SpecialiteMedicale(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/ClasseTherapeutique.java

```java
package com.lims.referential.enums.medicaments;

public enum ClasseTherapeutique {
    ANTALGIQUE_ANTIPYRETIQUE("Antalgique/Antipyrétique"),
    ANTI_INFLAMMATOIRE("Anti-inflammatoire"),
    ANTIBIOTIQUE("Antibiotique"),
    ANTIVIRAL("Antiviral"),
    ANTIFONGIQUE("Antifongique"),
    ANTICOAGULANT("Anticoagulant"),
    ANTIAGREGANT_PLAQUETTAIRE("Antiagrégant plaquettaire"),
    ANTIHYPERTENSEUR("Antihypertenseur"),
    DIURETIQUE("Diurétique"),
    CARDIOTONIQUE("Cardiotonique"),
    BRONCHODILATATEUR("Bronchodilatateur"),
    CORTICOIDE("Corticoïde"),
    IMMUNOSUPPRESSEUR("Immunosuppresseur"),
    ANTIDEPRESSEUR("Antidépresseur"),
    ANXIOLYTIQUE("Anxiolytique"),
    ANTICONVULSIVANT("Anticonvulsivant"),
    HYPNOTIQUE("Hypnotique"),
    ANTIDIABETIQUE("Antidiabétique"),
    HYPOLIPEMIANT("Hypolipémiant"),
    ANTIHISTAMINIQUE("Antihistaminique"),
    GASTROPROTECTEUR("Gastroprotecteur"),
    LAXATIF("Laxatif"),
    ANTIDIARRHEIQUE("Antidiarrhéique"),
    CONTRACEPTIF("Contraceptif"),
    HORMONE("Hormone"),
    VITAMINE("Vitamine"),
    MINERAL("Minéral"),
    AUTRE("Autre");

    private final String libelle;

    ClasseTherapeutique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/FormePharmaceutique.java

```java
package com.lims.referential.enums.medicaments;

public enum FormePharmaceutique {
    COMPRIME("Comprimé"),
    GELULE("Gélule"),
    CAPSULE("Capsule"),
    SIROP("Sirop"),
    SOLUTION_BUVABLE("Solution buvable"),
    SUSPENSION_BUVABLE("Suspension buvable"),
    POUDRE("Poudre"),
    GRANULES("Granulés"),
    SACHET("Sachet"),
    AMPOULE_BUVABLE("Ampoule buvable"),
    GOUTTES("Gouttes"),
    SPRAY("Spray"),
    AEROSOL("Aérosol"),
    INHALATEUR("Inhalateur"),
    INJECTION("Injectable"),
    PERFUSION("Perfusion"),
    SUPPOSITOIRE("Suppositoire"),
    OVULE("Ovule"),
    CREME("Crème"),
    POMMADE("Pommade"),
    GEL("Gel"),
    LOTION("Lotion"),
    PATCH("Patch transdermique"),
    COLLYRE("Collyre"),
    AUTRE("Autre");

    private final String libelle;

    FormePharmaceutique(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/NiveauCriticite.java

```java
package com.lims.referential.enums.medicaments;

public enum NiveauCriticite {
    FAIBLE("Faible"),
    MODERE("Modéré"),
    ELEVE("Élevé"),
    CRITIQUE("Critique");

    private final String libelle;

    NiveauCriticite(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/StatutCommercialisation.java

```java
package com.lims.referential.enums.medicaments;

public enum StatutCommercialisation {
    COMMERCIALISE("Commercialisé"),
    ARRETE("Arrêté"),
    SUSPENDU("Suspendu"),
    RETIRE("Retiré du marché"),
    EN_COURS("En cours d'autorisation");

    private final String libelle;

    StatutCommercialisation(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/TypeInteraction.java

```java
package com.lims.referential.enums.medicaments;

public enum TypeInteraction {
    INTERFERENCE("Interférence"),
    FAUX_POSITIF("Faux positif"),
    FAUX_NEGATIF("Faux négatif"),
    MODIFICATION_VALEURS("Modification des valeurs"),
    CONTRINDICATION("Contre-indication"),
    PRECAUTION("Précaution");

    private final String libelle;

    TypeInteraction(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/medicaments/VoieAdministration.java

```java
package com.lims.referential.enums.medicaments;

public enum VoieAdministration {
    ORALE("Orale"),
    INTRAVEINEUSE("Intraveineuse"),
    INTRAMUSCULAIRE("Intramusculaire"),
    SOUS_CUTANEE("Sous-cutanée"),
    INTRADERMIQUE("Intradermique"),
    TOPIQUE("Topique"),
    RECTALE("Rectale"),
    VAGINALE("Vaginale"),
    OCULAIRE("Oculaire"),
    NASALE("Nasale"),
    INHALEE("Inhalée"),
    SUBLINGUALE("Sublinguale"),
    TRANSDERMIQUE("Transdermique"),
    AUTRE("Autre");

    private final String libelle;

    VoieAdministration(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/mutuelles/ModeTransmission.java

```java
package com.lims.referential.enums.mutuelles;

public enum ModeTransmission {
    NOEMIE("Noémie"),
    EDIFACT("EDIFACT"),
    PAPIER("Papier"),
    B2B("B2B"),
    API("API"),
    EMAIL("Email"),
    AUTRE("Autre");

    private final String libelle;

    ModeTransmission(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/mutuelles/TypeOrganisme.java

```java
package com.lims.referential.enums.mutuelles;

public enum TypeOrganisme {
    CPAM("Caisse Primaire d'Assurance Maladie"),
    MUTUELLE("Mutuelle"),
    ASSURANCE("Compagnie d'assurance"),
    CMUC("Couverture Maladie Universelle Complémentaire"),
    INSTITUTION_PREVOYANCE("Institution de prévoyance"),
    AUTRE("Autre");

    private final String libelle;

    TypeOrganisme(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/patient/NiveauAlerte.java

```java
package com.lims.referential.enums.patient;

public enum NiveauAlerte {
    NORMAL("Normal"),
    WARNING("Attention"),
    CRITICAL("Critique");

    private final String libelle;

    NiveauAlerte(String libelle) {
        this.libelle = libelle;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/enums/patient/PrioritePreleveur.java

```java
package com.lims.referential.enums.patient;

public enum PrioritePreleveur {
    NORMALE(1, "Normale"),
    PRIORITAIRE(2, "Prioritaire"),
    URGENTE(3, "Urgente");

    private final int niveau;
    private final String libelle;

    PrioritePreleveur(int niveau, String libelle) {
        this.niveau = niveau;
        this.libelle = libelle;
    }

    public int getNiveau() {
        return niveau;
    }

    public String getLibelle() {
        return libelle;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/exception/GlobalExceptionHandler.java

```java
package com.lims.referential.exception;

import com.lims.referential.dto.response.ErrorResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Gestionnaire global des exceptions pour le service référentiel
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Gestion des ressources non trouvées (404)
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleResourceNotFound(
            ResourceNotFoundException ex, HttpServletRequest request) {

        log.warn("Ressource non trouvée: {}", ex.getMessage());

        ErrorResponseDTO error = ErrorResponseDTO.of(
                HttpStatus.NOT_FOUND.value(),
                "Resource Not Found",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Gestion des erreurs de validation des DTOs (400)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDTO> handleValidationErrors(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        log.warn("Erreur de validation: {}", ex.getMessage());

        Map<String, List<String>> validationErrors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();

            validationErrors.computeIfAbsent(fieldName, k -> new java.util.ArrayList<>())
                    .add(errorMessage);
        });

        ErrorResponseDTO error = ErrorResponseDTO.builder()
                .timestamp(java.time.LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Failed")
                .message("Erreurs de validation dans les données fournies")
                .path(request.getRequestURI())
                .validationErrors(validationErrors)
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Gestion des violations de contraintes (400)
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponseDTO> handleConstraintViolation(
            ConstraintViolationException ex, HttpServletRequest request) {

        log.warn("Violation de contrainte: {}", ex.getMessage());

        Map<String, List<String>> validationErrors = new HashMap<>();

        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            String fieldName = violation.getPropertyPath().toString();
            String errorMessage = violation.getMessage();

            validationErrors.computeIfAbsent(fieldName, k -> new java.util.ArrayList<>())
                    .add(errorMessage);
        }

        ErrorResponseDTO error = ErrorResponseDTO.builder()
                .timestamp(java.time.LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Constraint Violation")
                .message("Violation des contraintes de validation")
                .path(request.getRequestURI())
                .validationErrors(validationErrors)
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Gestion des arguments invalides (400)
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponseDTO> handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest request) {

        log.warn("Argument invalide: {}", ex.getMessage());

        ErrorResponseDTO error = ErrorResponseDTO.of(
                HttpStatus.BAD_REQUEST.value(),
                "Bad Request",
                ex.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Gestion des erreurs de type de paramètre (400)
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponseDTO> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {

        log.warn("Erreur de type de paramètre: {} pour le paramètre {}",
                ex.getValue(), ex.getName());

        String message = String.format("Valeur invalide '%s' pour le paramètre '%s'. Type attendu: %s",
                ex.getValue(), ex.getName(), ex.getRequiredType().getSimpleName());

        ErrorResponseDTO error = ErrorResponseDTO.of(
                HttpStatus.BAD_REQUEST.value(),
                "Type Mismatch",
                message,
                request.getRequestURI()
        );

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Gestion des violations d'intégrité de données (409)
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponseDTO> handleDataIntegrityViolation(
            DataIntegrityViolationException ex, HttpServletRequest request) {

        log.error("Violation d'intégrité des données", ex);

        String message = "Violation d'intégrité des données";

        // Analyser le message d'erreur pour fournir des détails plus précis
        String causeMessage = ex.getMostSpecificCause().getMessage();
        if (causeMessage != null) {
            if (causeMessage.contains("unique")) {
                message = "Cette ressource existe déjà dans le système";
            } else if (causeMessage.contains("foreign key")) {
                message = "Référence vers une ressource qui n'existe pas";
            } else if (causeMessage.contains("not null")) {
                message = "Champ obligatoire manquant";
            }
        }

        ErrorResponseDTO error = ErrorResponseDTO.of(
                HttpStatus.CONFLICT.value(),
                "Data Integrity Violation",
                message,
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Gestion de toutes les autres exceptions (500)
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> handleGenericException(
            Exception ex, HttpServletRequest request) {

        log.error("Erreur interne du serveur", ex);

        ErrorResponseDTO error = ErrorResponseDTO.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "Une erreur inattendue s'est produite. Veuillez réessayer plus tard.",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}

```

# lims-ref-service/src/main/java/com/lims/referential/exception/ResourceNotFoundException.java

```java
package com.lims.referential.exception;

/**
 * Exception lancée quand une ressource n'est pas trouvée
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public ResourceNotFoundException(String resourceType, String identifier) {
        super(String.format("%s non trouvé avec l'identifiant: %s", resourceType, identifier));
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/AnalyseMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.Analyse;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Analyse et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface AnalyseMapper {

    /**
     * Convertit une entité Analyse en DTO de réponse
     */
    AnalyseResponseDTO toResponseDTO(Analyse analyse);

    /**
     * Convertit un DTO de requête en entité Analyse
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Analyse toEntity(AnalyseRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(AnalyseRequestDTO requestDTO, @MappingTarget Analyse analyse);
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/GeographiqueMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.Geographique;
import com.lims.referential.dto.request.GeographiqueRequestDTO;
import com.lims.referential.dto.response.GeographiqueResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Geographique et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface GeographiqueMapper {

    /**
     * Convertit une entité Geographique en DTO de réponse
     */
    GeographiqueResponseDTO toResponseDTO(Geographique geographique);

    /**
     * Convertit un DTO de requête en entité Geographique
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Geographique toEntity(GeographiqueRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(GeographiqueRequestDTO requestDTO, @MappingTarget Geographique geographique);
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/LaboratoireMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.dto.request.MedicamentRequestDTO;
import com.lims.referential.entity.Laboratoire;
import com.lims.referential.dto.request.LaboratoireRequestDTO;
import com.lims.referential.dto.response.LaboratoireResponseDTO;
import com.lims.referential.entity.Medicament;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Laboratoire et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface LaboratoireMapper {

    /**
     * Convertit une entité Laboratoire en DTO de réponse
     */
    @Mapping(target = "contact", source = ".")
    @Mapping(target = "informationsPratiques", source = ".")
    @Mapping(target = "capacitesTechniques", source = ".")
    LaboratoireResponseDTO toResponseDTO(Laboratoire laboratoire);

    /**
     * Convertit un DTO de requête en entité Laboratoire
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)     // ✅ Corrigé
    @Mapping(target = "dateModification", ignore = true) // ✅ Corrigé
    @Mapping(target = "creePar", ignore = true)          // ✅ Corrigé
    @Mapping(target = "modifiePar", ignore = true)       // ✅ Corrigé
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "horairesOuverture", source = "informationsPratiques.horairesOuverture")
    @Mapping(target = "parkingDisponible", source = "informationsPratiques.parkingDisponible")
    @Mapping(target = "accesHandicapes", source = "informationsPratiques.accesHandicapes")
    @Mapping(target = "transportPublic", source = "informationsPratiques.transportPublic")
    @Mapping(target = "analysesDisponibles", source = "capacitesTechniques.analysesDisponibles")
    @Mapping(target = "specialitesTechniques", source = "capacitesTechniques.specialitesTechniques")
    @Mapping(target = "equipementsSpeciaux", source = "capacitesTechniques.equipementsSpeciaux")
    Laboratoire toEntity(LaboratoireRequestDTO requestDTO);

    /**
     * Met à jour une entité Laboratoire existante avec les données du DTO
     * ❌ ERREUR CORRIGÉE: Utilise LaboratoireRequestDTO au lieu de MedicamentRequestDTO
     * ❌ ERREUR CORRIGÉE: Target Laboratoire au lieu de Medicament
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)     // ✅ Propriétés correctes
    @Mapping(target = "dateModification", ignore = true) // ✅ selon l'entité Medicament
    @Mapping(target = "creePar", ignore = true)          // ✅ fournie
    @Mapping(target = "modifiePar", ignore = true)       // ✅
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(LaboratoireRequestDTO requestDTO, @MappingTarget Laboratoire laboratoire);

    // ============================================
    // MÉTHODES POUR MEDICAMENT (SI NÉCESSAIRES)
    // ============================================

    /**
     * Si vous avez besoin de mapper des médicaments aussi, ajoutez cette méthode séparée
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    // Mappings spécifiques au médicament selon votre MedicamentRequestDTO
    @Mapping(target = "denomination", source = "nomCommercial")  // ✅ Mapping nom commercial -> denomination
    @Mapping(target = "codeCis", source = "codeCip")             // ✅ Si vous voulez mapper CIP -> CIS
    @Mapping(target = "formePharma", source = "formePharmaceutique")
    @Mapping(target = "voiesAdmin", source = "voieAdministration")
    @Mapping(target = "laboratoireTitulaire", source = "laboratoireFabricant")
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateMedicamentFromDTO(MedicamentRequestDTO requestDTO, @MappingTarget Medicament medicament);

    /**
     * Convertit MedicamentRequestDTO en entité Medicament
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "denomination", source = "nomCommercial")
    @Mapping(target = "codeCis", source = "codeCip")  // ⚠️ Attention: CIP ≠ CIS selon ANSM
    @Mapping(target = "formePharma", source = "formePharmaceutique")
    @Mapping(target = "voiesAdmin", source = "voieAdministration")
    @Mapping(target = "laboratoireTitulaire", source = "laboratoireFabricant")
    @Mapping(target = "statutBdm", source = "statutCommercialisation")
    Medicament medicamentRequestToEntity(MedicamentRequestDTO requestDTO);
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/MedecinMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.Medecin;
import com.lims.referential.dto.request.MedecinRequestDTO;
import com.lims.referential.dto.response.MedecinResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Medecin et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface MedecinMapper {

    MedecinResponseDTO toResponseDTO(Medecin medecin);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    Medecin toEntity(MedecinRequestDTO requestDTO);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(MedecinRequestDTO requestDTO, @MappingTarget Medecin medecin);
}

```

# lims-ref-service/src/main/java/com/lims/referential/mapper/MedicamentMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.entity.Medicament;
import org.mapstruct.*;

import java.util.List;
import java.util.UUID;

/**
 * Mapper MapStruct pour les entités Medicament.
 * Convertit entre entités JPA et DTOs REST.
 */
@Mapper(
        componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface MedicamentMapper {

    // ============================================
    // CONVERSION ENTITY -> DTO
    // ============================================

    /**
     * Convertit une entité Medicament en MedicamentResponse
     */
    @Mapping(target = "id", source = "id", qualifiedByName = "uuidToString")
    @Mapping(target = "actif", source = "actif")
    MedicamentResponse toResponse(Medicament medicament);

    /**
     * Convertit une liste d'entités en liste de DTOs
     */
    List<MedicamentResponse> toResponseList(List<Medicament> medicaments);

    // ============================================
    // CONVERSION DTO -> ENTITY
    // ============================================

    /**
     * Convertit une demande de création en entité
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    Medicament toEntity(CreateMedicamentRequest request);

    /**
     * Met à jour une entité existante avec les données de la requête
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "dateCreation", ignore = true)
    @Mapping(target = "dateModification", ignore = true)
    @Mapping(target = "creePar", ignore = true)
    @Mapping(target = "modifiePar", ignore = true)
    @Mapping(target = "version", ignore = true)
    void updateEntityFromRequest(UpdateMedicamentRequest request, @MappingTarget Medicament medicament);

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Convertit UUID en String
     */
    @Named("uuidToString")
    default String uuidToString(UUID uuid) {
        return uuid != null ? uuid.toString() : null;
    }

    /**
     * Convertit String en UUID
     */
    @Named("stringToUuid")
    default UUID stringToUuid(String str) {
        return str != null ? UUID.fromString(str) : null;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/MutuelleMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.Mutuelle;
import com.lims.referential.dto.request.MutuelleRequestDTO;
import com.lims.referential.dto.response.MutuelleResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités Mutuelle et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface MutuelleMapper {

    /**
     * Convertit une entité Mutuelle en DTO de réponse
     */
    @Mapping(target = "adresse", source = ".")
    @Mapping(target = "contact", source = ".")
    @Mapping(target = "priseEnCharge", source = ".")
    @Mapping(target = "facturation", source = ".")
    MutuelleResponseDTO toResponseDTO(Mutuelle mutuelle);

    /**
     * Convertit un DTO de requête en entité Mutuelle
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "adresseLigne1", source = "adresse.ligne1")
    @Mapping(target = "adresseLigne2", source = "adresse.ligne2")
    @Mapping(target = "codePostal", source = "adresse.codePostal")
    @Mapping(target = "ville", source = "adresse.ville")
    @Mapping(target = "departement", source = "adresse.departement")
    @Mapping(target = "region", source = "adresse.region")
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "tauxBaseRemboursement", source = "priseEnCharge.tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "priseEnCharge.plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "priseEnCharge.franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "priseEnCharge.analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "priseEnCharge.analysesExclues")
    @Mapping(target = "codesFacturation", source = "facturation.codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "facturation.delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "facturation.modeTransmission")
    Mutuelle toEntity(MutuelleRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "adresseLigne1", source = "adresse.ligne1")
    @Mapping(target = "adresseLigne2", source = "adresse.ligne2")
    @Mapping(target = "codePostal", source = "adresse.codePostal")
    @Mapping(target = "ville", source = "adresse.ville")
    @Mapping(target = "departement", source = "adresse.departement")
    @Mapping(target = "region", source = "adresse.region")
    @Mapping(target = "telephone", source = "contact.telephone")
    @Mapping(target = "fax", source = "contact.fax")
    @Mapping(target = "email", source = "contact.email")
    @Mapping(target = "siteWeb", source = "contact.siteWeb")
    @Mapping(target = "tauxBaseRemboursement", source = "priseEnCharge.tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "priseEnCharge.plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "priseEnCharge.franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "priseEnCharge.analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "priseEnCharge.analysesExclues")
    @Mapping(target = "codesFacturation", source = "facturation.codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "facturation.delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "facturation.modeTransmission")
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(MutuelleRequestDTO requestDTO, @MappingTarget Mutuelle mutuelle);

    // Méthodes de mapping pour les sous-objets
    @Mapping(target = "ligne1", source = "adresseLigne1")
    @Mapping(target = "ligne2", source = "adresseLigne2")
    @Mapping(target = "codePostal", source = "codePostal")
    @Mapping(target = "ville", source = "ville")
    @Mapping(target = "departement", source = "departement")
    @Mapping(target = "region", source = "region")
    MutuelleResponseDTO.AdresseMutuelleResponseDTO toAdresseResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "telephone", source = "telephone")
    @Mapping(target = "fax", source = "fax")
    @Mapping(target = "email", source = "email")
    @Mapping(target = "siteWeb", source = "siteWeb")
    MutuelleResponseDTO.ContactMutuelleResponseDTO toContactResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "tauxBaseRemboursement", source = "tauxBaseRemboursement")
    @Mapping(target = "plafondAnnuelEuro", source = "plafondAnnuelEuro")
    @Mapping(target = "franchiseEuro", source = "franchiseEuro")
    @Mapping(target = "analysesCouvertes", source = "analysesCouvertes")
    @Mapping(target = "analysesExclues", source = "analysesExclues")
    MutuelleResponseDTO.PriseEnChargeResponseDTO toPriseEnChargeResponseDTO(Mutuelle mutuelle);

    @Mapping(target = "codesFacturation", source = "codesFacturation")
    @Mapping(target = "delaiPaiementJours", source = "delaiPaiementJours")
    @Mapping(target = "modeTransmission", source = "modeTransmission")
    MutuelleResponseDTO.FacturationResponseDTO toFacturationResponseDTO(Mutuelle mutuelle);

    // Mapping des analyses couvertes
    MutuelleResponseDTO.AnalyseCouvertureResponseDTO toAnalyseCouvertureResponseDTO(Mutuelle.AnalyseCouverture analyseCouverture);
    Mutuelle.AnalyseCouverture toAnalyseCouvertureEntity(MutuelleRequestDTO.AnalyseCouvertureRequestDTO analyseCouvertureRequestDTO);
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/PatientSpecificityMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.PatientSpecificity;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités PatientSpecificity et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE,
        uses = {SpecificityCategoryMapper.class})
public interface PatientSpecificityMapper {

    /**
     * Convertit une entité PatientSpecificity en DTO de réponse
     */
    PatientSpecificityResponseDTO toResponseDTO(PatientSpecificity patientSpecificity);

    /**
     * Convertit un DTO de requête en entité PatientSpecificity
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "category", ignore = true)
    PatientSpecificity toEntity(PatientSpecificityRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @Mapping(target = "category", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(PatientSpecificityRequestDTO requestDTO, @MappingTarget PatientSpecificity patientSpecificity);
}
```

# lims-ref-service/src/main/java/com/lims/referential/mapper/SpecificityCategoryMapper.java

```java
package com.lims.referential.mapper;

import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.dto.request.SpecificityCategoryRequestDTO;
import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import org.mapstruct.*;

/**
 * Mapper pour la conversion entre entités SpecificityCategory et DTOs
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface SpecificityCategoryMapper {

    /**
     * Convertit une entité SpecificityCategory en DTO de réponse
     */
    @Mapping(target = "specificities", ignore = true) // Éviter les références circulaires
    SpecificityCategoryResponseDTO toResponseDTO(SpecificityCategory specificityCategory);

    /**
     * Convertit un DTO de requête en entité SpecificityCategory
     */
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "specificities", ignore = true)
    SpecificityCategory toEntity(SpecificityCategoryRequestDTO requestDTO);

    /**
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "specificities", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(SpecificityCategoryRequestDTO requestDTO, @MappingTarget SpecificityCategory specificityCategory);
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/AnalyseRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.Analyse;
import com.lims.referential.enums.analyses.CategorieAnalyse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AnalyseRepository extends JpaRepository<Analyse, UUID> {

    /**
     * Recherche une analyse par son code NABM
     */
    Optional<Analyse> findByCodeNabmAndActifTrue(String codeNabm);

    /**
     * Recherche par catégorie
     */
    Page<Analyse> findByCategorieAndActifTrue(CategorieAnalyse categorie, Pageable pageable);

    /**
     * Recherche textuelle avec PostgreSQL full-text search
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true 
        AND (UPPER(a.libelle) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(a.codeNabm) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(a.description) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY 
            CASE WHEN UPPER(a.codeNabm) = UPPER(:searchTerm) THEN 1
                 WHEN UPPER(a.libelle) = UPPER(:searchTerm) THEN 2
                 WHEN UPPER(a.codeNabm) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 3
                 WHEN UPPER(a.libelle) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 4
                 ELSE 5 END
        """)
    Page<Analyse> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Auto-complétion pour la recherche
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true 
        AND (UPPER(a.libelle) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(a.codeNabm) LIKE UPPER(CONCAT(:prefix, '%')))
        ORDER BY 
            CASE WHEN UPPER(a.codeNabm) LIKE UPPER(CONCAT(:prefix, '%')) THEN 1
                 ELSE 2 END,
            LENGTH(a.libelle)
        """)
    List<Analyse> findSuggestions(@Param("prefix") String prefix, Pageable pageable);

    /**
     * Filtrage multi-critères
     */
    @Query("""
        SELECT a FROM Analyse a 
        WHERE a.actif = true
        AND (:categorie IS NULL OR a.categorie = :categorie)
        AND (:sousCategorie IS NULL OR UPPER(a.sousCategorie) = UPPER(:sousCategorie))
        AND (:actif IS NULL OR a.actif = :actif)
        """)
    Page<Analyse> findWithFilters(
            @Param("categorie") CategorieAnalyse categorie,
            @Param("sousCategorie") String sousCategorie,
            @Param("actif") Boolean actif,
            Pageable pageable);

    /**
     * Statistiques des analyses
     */
    @Query("SELECT COUNT(a) FROM Analyse a WHERE a.actif = true")
    long countActiveAnalyses();

    @Query("SELECT a.categorie, COUNT(a) FROM Analyse a WHERE a.actif = true GROUP BY a.categorie")
    List<Object[]> getAnalysesByCategory();
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/GeographiqueRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.Geographique;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface GeographiqueRepository extends JpaRepository<Geographique, UUID> {

    /**
     * Recherche par code postal
     */
    List<Geographique> findByCodePostalAndActifTrue(String codePostal);

    /**
     * Recherche par nom de commune
     */
    List<Geographique> findByNomCommuneContainingIgnoreCaseAndActifTrue(String nomCommune);

    /**
     * Recherche par département
     */
    List<Geographique> findByDepartementAndActifTrue(String departement);

    /**
     * Recherche par code département
     */
    List<Geographique> findByCodeDepartementAndActifTrue(String codeDepartement);

    /**
     * Recherche par région
     */
    List<Geographique> findByRegionAndActifTrue(String region);

    /**
     * Recherche par code région
     */
    List<Geographique> findByCodeRegionAndActifTrue(String codeRegion);

    /**
     * Recherche textuelle dans les communes
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND (UPPER(g.nomCommune) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR g.codePostal LIKE CONCAT(:searchTerm, '%')
             OR UPPER(g.departement) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY g.nomCommune
        """)
    Page<Geographique> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Communes dans une zone de desserte d'un laboratoire
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND function('jsonb_exists', g.laboratoiresZone, cast(:laboratoireId as string)) = true
    """)
    List<Geographique> findZonesDesserteByLaboratoire(@Param("laboratoireId") UUID laboratoireId);

    /**
     * Communes avec coordonnées GPS
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND g.latitude IS NOT NULL 
        AND g.longitude IS NOT NULL
        """)
    List<Geographique> findWithCoordinates();

    /**
     * Compter les départements distincts
     */
    @Query("SELECT COUNT(DISTINCT g.departement) FROM Geographique g WHERE g.actif = true")
    long countDistinctDepartements();

    /**
     * Compter les régions distinctes
     */
    @Query("SELECT COUNT(DISTINCT g.region) FROM Geographique g WHERE g.actif = true")
    long countDistinctRegions();

    /**
     * Statistiques par département
     */
    @Query("SELECT g.departement, COUNT(g) FROM Geographique g WHERE g.actif = true GROUP BY g.departement ORDER BY COUNT(g) DESC")
    List<Object[]> countByDepartement();

    /**
     * Statistiques par région
     */
    @Query("SELECT g.region, COUNT(g) FROM Geographique g WHERE g.actif = true GROUP BY g.region ORDER BY COUNT(g) DESC")
    List<Object[]> countByRegion();

    /**
     * Communes les plus peuplées
     */
    @Query("""
        SELECT g FROM Geographique g 
        WHERE g.actif = true 
        AND g.population IS NOT NULL 
        ORDER BY g.population DESC
        """)
    List<Geographique> findTopByPopulation(Pageable pageable);

    /**
     * Recherche par code INSEE
     */
    List<Geographique> findByCodeCommuneAndActifTrue(String codeCommune);
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/LaboratoireRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.Laboratoire;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour la gestion des laboratoires en base de données.
 * Inclut les méthodes de recherche géographique et de filtrage.
 */
@Repository
public interface LaboratoireRepository extends JpaRepository<Laboratoire, UUID> {

    // ============================================
    // REQUÊTES DE BASE
    // ============================================

    /**
     * Trouve tous les laboratoires actifs (non supprimés)
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    List<Laboratoire> findAllActive();

    /**
     * Trouve tous les laboratoires actifs avec pagination
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    Page<Laboratoire> findAllActive(Pageable pageable);

    /**
     * Trouve un laboratoire actif par ID
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.id = :id AND l.actif = true AND l.deletedAt IS NULL")
    Optional<Laboratoire> findActiveById(@Param("id") UUID id);

    /**
     * Compte les laboratoires actifs
     */
    @Query("SELECT COUNT(l) FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL")
    long countActive();

    // ============================================
    // REQUÊTES DE RECHERCHE TEXTUELLE
    // ============================================

    /**
     * Recherche de laboratoires par terme (nom, ville, adresse)
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND (LOWER(l.nom) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.ville) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.adresse) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
             OR LOWER(l.codePostal) LIKE LOWER(CONCAT('%', :searchTerm, '%')))
        ORDER BY l.nom
        """)
    Page<Laboratoire> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Recherche par ville
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND LOWER(l.ville) = LOWER(:ville)")
    List<Laboratoire> findByVille(@Param("ville") String ville);

    /**
     * Recherche par code postal
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.codePostal = :codePostal")
    List<Laboratoire> findByCodePostal(@Param("codePostal") String codePostal);

    // ============================================
    // REQUÊTES GÉOGRAPHIQUES (SIMPLIFIÉES)
    // ============================================

    /**
     * Recherche géographique simplifiée par zone (à adapter selon vos coordonnées stockées)
     * Note: Cette implémentation est basique. Pour une vraie recherche géographique,
     * il faudrait stocker latitude/longitude et utiliser des fonctions spatiales.
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND l.ville IN (
            SELECT DISTINCT l2.ville FROM Laboratoire l2 
            WHERE l2.actif = true AND l2.deletedAt IS NULL
        )
        ORDER BY l.ville, l.nom
        """)
    List<Laboratoire> findByGeolocation(
            @Param("latitude") BigDecimal latitude,
            @Param("longitude") BigDecimal longitude,
            @Param("radius") Integer radius);

    /**
     * Version alternative avec coordonnées géographiques (si vous avez ces champs)
     * Décommentez et adaptez si vous ajoutez latitude/longitude à l'entité
     */
    /*
    @Query(value = """
        SELECT * FROM lims_referential.laboratoires l
        WHERE l.actif = true AND l.deleted_at IS NULL
        AND ST_DWithin(
            ST_SetSRID(ST_Point(l.longitude, l.latitude), 4326),
            ST_SetSRID(ST_Point(:longitude, :latitude), 4326),
            :radius * 1000
        )
        ORDER BY ST_Distance(
            ST_SetSRID(ST_Point(l.longitude, l.latitude), 4326),
            ST_SetSRID(ST_Point(:longitude, :latitude), 4326)
        )
        """, nativeQuery = true)
    List<Laboratoire> findByGeolocationExact(
            @Param("latitude") BigDecimal latitude,
            @Param("longitude") BigDecimal longitude,
            @Param("radius") Integer radius);
    */

    // ============================================
    // REQUÊTES PAR CAPACITÉS TECHNIQUES
    // ============================================

    /**
     * Trouve les laboratoires proposant une analyse spécifique
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.analysesDisponibles a
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND a = :codeAnalyse
        ORDER BY l.nom
        """)
    List<Laboratoire> findByAnalyseDisponible(@Param("codeAnalyse") String codeAnalyse);

    /**
     * Trouve les laboratoires ayant une spécialité technique
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.specialitesTechniques s
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND s = :specialite
        ORDER BY l.nom
        """)
    List<Laboratoire> findBySpecialiteTechnique(@Param("specialite") String specialite);

    /**
     * Trouve les laboratoires avec un équipement spécial
     */
    @Query("""
        SELECT DISTINCT l FROM Laboratoire l 
        JOIN l.equipementsSpeciaux e
        WHERE l.actif = true AND l.deletedAt IS NULL
        AND e = :equipement
        ORDER BY l.nom
        """)
    List<Laboratoire> findByEquipementSpecial(@Param("equipement") String equipement);

    // ============================================
    // REQUÊTES DE COMMODITÉS
    // ============================================

    /**
     * Trouve les laboratoires avec parking
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.parkingDisponible = true")
    List<Laboratoire> findWithParking();

    /**
     * Trouve les laboratoires accessibles aux handicapés
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.accesHandicapes = true")
    List<Laboratoire> findAccessibleToDisabled();

    /**
     * Trouve les laboratoires avec transport public
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND l.transportPublic IS NOT NULL")
    List<Laboratoire> findWithPublicTransport();

    // ============================================
    // REQUÊTES STATISTIQUES
    // ============================================

    /**
     * Statistiques par ville
     */
    @Query("""
        SELECT l.ville, COUNT(l) 
        FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        GROUP BY l.ville 
        ORDER BY COUNT(l) DESC
        """)
    List<Object[]> countByVille();

    /**
     * Nombre d'analyses disponibles par laboratoire
     */
    @Query("""
        SELECT l.nom, SIZE(l.analysesDisponibles)
        FROM Laboratoire l 
        WHERE l.actif = true AND l.deletedAt IS NULL
        ORDER BY SIZE(l.analysesDisponibles) DESC
        """)
    List<Object[]> countAnalysesByLaboratoire();

    // ============================================
    // REQUÊTES DE MAINTENANCE
    // ============================================

    /**
     * Trouve les laboratoires sans email
     */
    @Query("SELECT l FROM Laboratoire l WHERE l.actif = true AND l.deletedAt IS NULL AND (l.email IS NULL OR l.email = '')")
    List<Laboratoire> findWithoutEmail();

    /**
     * Trouve les laboratoires sans analyses disponibles
     */
    @Query(value = """
        SELECT * FROM lims_referential.laboratoires l 
        WHERE l.actif = true 
        AND l.deleted_at IS NULL 
        AND (l.analyses_disponibles IS NULL OR l.analyses_disponibles = '[]'::jsonb)
        """, nativeQuery = true)
    List<Laboratoire> findWithoutAnalyses();

    /**
     * Supprime définitivement les laboratoires marqués comme supprimés depuis plus de X jours
     */
    @Query("DELETE FROM Laboratoire l WHERE l.deletedAt IS NOT NULL AND l.deletedAt < :cutoffDate")
    void permanentlyDeleteOldSoftDeleted(@Param("cutoffDate") java.time.LocalDateTime cutoffDate);
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/MedecinRepository.java

```java
// MedecinRepository.java
package com.lims.referential.repository;

import com.lims.referential.entity.Medecin;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MedecinRepository extends JpaRepository<Medecin, UUID> {

    /**
     * Recherche un médecin par son numéro RPPS
     */
    Optional<Medecin> findByNumeroRppsAndActifTrue(String numeroRpps);

    /**
     * Recherche par spécialité principale
     */
    Page<Medecin> findBySpecialitePrincipaleAndActifTrue(String specialite, Pageable pageable);

    /**
     * Recherche par ville
     */
    Page<Medecin> findByAdresse_VilleAndActifTrue(String ville, Pageable pageable);

    /**
     * Recherche par département
     */
    Page<Medecin> findByAdresse_DepartementAndActifTrue(String departement, Pageable pageable);

    /**
     * Recherche textuelle avec PostgreSQL full-text search
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.prenom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.numeroRpps) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.specialitePrincipale) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY 
            CASE WHEN UPPER(m.numeroRpps) = UPPER(:searchTerm) THEN 1
                 WHEN UPPER(m.nom) = UPPER(:searchTerm) THEN 2
                 WHEN UPPER(m.nom) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 3
                 WHEN UPPER(m.prenom) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 4
                 ELSE 5 END,
            m.nom, m.prenom
        """)
    Page<Medecin> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Auto-complétion pour la recherche
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(m.prenom) LIKE UPPER(CONCAT(:prefix, '%'))
             OR UPPER(m.numeroRpps) LIKE UPPER(CONCAT(:prefix, '%')))
        ORDER BY m.nom, m.prenom
        """)
    List<Medecin> findSuggestions(@Param("prefix") String prefix, Pageable pageable);

    /**
     * Filtrage multi-critères
     */
    @Query("""
        SELECT m FROM Medecin m 
        WHERE m.actif = true
        AND (:specialite IS NULL OR m.specialitePrincipale = :specialite)
        AND (:ville IS NULL OR UPPER(m.adresse.ville) = UPPER(:ville))
        AND (:departement IS NULL OR UPPER(m.adresse.departement) = UPPER(:departement))
        """)
    Page<Medecin> findWithFilters(
            @Param("specialite") String specialite,
            @Param("ville") String ville,
            @Param("departement") String departement,
            Pageable pageable);

    /**
     * Compter les médecins par spécialité
     */
    @Query("SELECT m.specialitePrincipale, COUNT(m) FROM Medecin m WHERE m.actif = true GROUP BY m.specialitePrincipale")
    List<Object[]> countBySpecialite();

    /**
     * Compter les médecins par département
     */
    @Query("SELECT m.adresse.departement, COUNT(m) FROM Medecin m WHERE m.actif = true GROUP BY m.adresse.departement")
    List<Object[]> countByDepartement();

    /**
     * Vérifier l'existence d'un RPPS
     */
    boolean existsByNumeroRppsAndActifTrue(String numeroRpps);
}

// MedicamentRepository.java


// MutuelleRepository.java


// GeographiqueRepository.java


// PatientSpecificityRepository.java


// SpecificityCategoryRepository.java

```

# lims-ref-service/src/main/java/com/lims/referential/repository/MedicamentRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.Medicament;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository pour la gestion des médicaments en base de données.
 * Utilise Spring Data JPA pour les opérations CRUD.
 */
@Repository
public interface MedicamentRepository extends JpaRepository<Medicament, UUID> {

    // ============================================
    // REQUÊTES DE BASE
    // ============================================

    /**
     * Trouve un médicament par son code CIS
     */
    Optional<Medicament> findByCodeCis(String codeCis);

    /**
     * Vérifie si un médicament existe avec le code CIS donné
     */
    boolean existsByCodeCis(String codeCis);

    /**
     * Récupère tous les médicaments actifs
     */
    List<Medicament> findByActifTrue();

    /**
     * Récupère tous les médicaments actifs avec pagination
     */
    Page<Medicament> findByActifTrue(Pageable pageable);

    /**
     * Compte le nombre de médicaments actifs
     */
    long countByActifTrue();

    // ============================================
    // REQUÊTES DE RECHERCHE
    // ============================================

    /**
     * Recherche de médicaments par dénomination (case insensitive)
     */
    List<Medicament> findByDenominationContainingIgnoreCase(String denomination);

    /**
     * Recherche de médicaments par laboratoire titulaire
     */
    List<Medicament> findByLaboratoireTitulaireContainingIgnoreCase(String laboratoire);

    /**
     * Recherche de médicaments par forme pharmaceutique
     */
    List<Medicament> findByFormePharmaContainingIgnoreCase(String formePharma);

    // ============================================
    // REQUÊTES SPÉCIALISÉES
    // ============================================

    /**
     * Récupère les médicaments remboursés (taux > 0)
     */
    List<Medicament> findByTauxRemboursementGreaterThan(Integer taux);

    /**
     * Récupère les médicaments sous surveillance renforcée
     */
    List<Medicament> findBySurveillanceRenforceeTrue();

    /**
     * Récupère les médicaments par statut AMM
     */
    List<Medicament> findByStatutAmm(String statutAmm);

    /**
     * Récupère les médicaments par statut BdM
     */
    List<Medicament> findByStatutBdm(String statutBdm);

    // ============================================
    // REQUÊTES NATIVES PERSONNALISÉES
    // ============================================

    /**
     * Recherche full-text dans plusieurs champs
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE (LOWER(m.denomination) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR LOWER(m.laboratoireTitulaire) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR LOWER(m.laboratoireExploitant) LIKE LOWER(CONCAT('%', :searchTerm, '%'))
           OR m.codeCis LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        AND m.actif = true
        ORDER BY m.denomination
        """)
    List<Medicament> searchMedicaments(@Param("searchTerm") String searchTerm);

    /**
     * Récupère les médicaments avec un taux de remboursement spécifique
     */
    @Query("SELECT m FROM Medicament m WHERE m.tauxRemboursement = :taux AND m.actif = true")
    List<Medicament> findByTauxRemboursementExact(@Param("taux") Integer taux);

    /**
     * Récupère les médicaments les plus récents
     */
    @Query("SELECT m FROM Medicament m WHERE m.actif = true ORDER BY m.dateCreation DESC")
    List<Medicament> findRecentMedicaments(Pageable pageable);

    /**
     * Statistiques : nombre de médicaments par laboratoire
     */
    @Query("""
        SELECT m.laboratoireTitulaire, COUNT(m) 
        FROM Medicament m 
        WHERE m.actif = true 
        GROUP BY m.laboratoireTitulaire 
        ORDER BY COUNT(m) DESC
        """)
    List<Object[]> countMedicamentsByLaboratoire();

    /**
     * Statistiques : répartition par forme pharmaceutique
     */
    @Query("""
        SELECT m.formePharma, COUNT(m) 
        FROM Medicament m 
        WHERE m.actif = true AND m.formePharma IS NOT NULL
        GROUP BY m.formePharma 
        ORDER BY COUNT(m) DESC
        """)
    List<Object[]> countMedicamentsByFormePharma();

    // ============================================
    // REQUÊTES DE MAINTENANCE
    // ============================================

    /**
     * Trouve les médicaments sans prix de vente
     */
    @Query("SELECT m FROM Medicament m WHERE m.prixVente IS NULL AND m.actif = true")
    List<Medicament> findMedicamentsSansPrix();

    /**
     * Trouve les médicaments avec des données incomplètes
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE m.actif = true 
        AND (m.denomination IS NULL OR m.denomination = '' 
             OR m.laboratoireTitulaire IS NULL OR m.laboratoireTitulaire = '')
        """)
    List<Medicament> findMedicamentsAvecDonneesIncompletes();

    /**
     * Supprime les médicaments inactifs (nettoyage)
     */
    @Query("DELETE FROM Medicament m WHERE m.actif = false")
    void deleteInactifs();
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/MutuelleRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.Mutuelle;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MutuelleRepository extends JpaRepository<Mutuelle, UUID> {

    /**
     * Recherche par code organisme
     */
    Optional<Mutuelle> findByCodeOrganismeAndActifTrue(String codeOrganisme);

    /**
     * Recherche par type d'organisme
     */
    Page<Mutuelle> findByTypeOrganismeAndActifTrue(String typeOrganisme, Pageable pageable);

    /**
     * Recherche par nom
     */
    Page<Mutuelle> findByNomContainingIgnoreCaseAndActifTrue(String nom, Pageable pageable);

    /**
     * Recherche textuelle
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND (UPPER(m.nom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.nomCommercial) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.codeOrganisme) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.typeOrganisme) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY m.nom
        """)
    Page<Mutuelle> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Mutuelles avec tiers payant
     */
    @Query(value = """
    SELECT * FROM lims_referential.mutuelles m 
    WHERE m.actif = true 
    AND m.deleted_at IS NULL
    AND m.tiers_payant = true
    """, nativeQuery = true)
    List<Mutuelle> findWithTiersPayant();

    /**
     * Recherche par mode de transmission
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND m.modeTransmission = :modeTransmission
        """)
    Page<Mutuelle> findByModeTransmission(@Param("modeTransmission") String modeTransmission, Pageable pageable);

    /**
     * Mutuelles couvrant une analyse spécifique
     */
    /**
     * Mutuelles couvrant une analyse spécifique
     * Correction pour PostgreSQL JSONB
     */
    @Query(value = """
    SELECT * FROM lims_referential.mutuelles m 
    WHERE m.actif = true 
    AND m.deleted_at IS NULL
    AND (
        EXISTS (
            SELECT 1 FROM jsonb_array_elements(m.analyses_couvertes) AS couverture
            WHERE couverture->>'codeNabm' = ?1
        )
        OR NOT (m.analyses_exclues @> to_jsonb(?1))
    )
    """, nativeQuery = true)
    List<Mutuelle> findCoveringAnalyse(String codeNabm);

    /**
     * Statistiques par type d'organisme
     */
    @Query("SELECT m.typeOrganisme, COUNT(m) FROM Mutuelle m WHERE m.actif = true GROUP BY m.typeOrganisme")
    List<Object[]> countByTypeOrganisme();

    /**
     * Mutuelles par région
     */
    @Query("SELECT m.region, COUNT(m) FROM Mutuelle m WHERE m.actif = true GROUP BY m.region")
    List<Object[]> countByRegion();

    /**
     * Mutuelles avec délai de paiement court
     */
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND m.delaiPaiementJours <= :delaiMaximum
        ORDER BY m.delaiPaiementJours
        """)
    List<Mutuelle> findByDelaiPaiementMaximum(@Param("delaiMaximum") Integer delaiMaximum);
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/PatientSpecificityRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.PatientSpecificity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PatientSpecificityRepository extends JpaRepository<PatientSpecificity, UUID> {

    /**
     * Recherche par catégorie
     */
    Page<PatientSpecificity> findByCategoryIdAndActifTrue(String categoryId, Pageable pageable);

    /**
     * Recherche par niveau d'alerte
     */
    Page<PatientSpecificity> findByNiveauAlerteAndActifTrue(String niveauAlerte, Pageable pageable);

    /**
     * Recherche textuelle avec mots-clés (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        ORDER BY ps.priorite_preleveur DESC, ps.titre
        """, nativeQuery = true)
    List<PatientSpecificity> searchByTerm(String searchTerm);

    /**
     * Version pageable pour la recherche textuelle
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        ORDER BY ps.priorite_preleveur DESC, ps.titre
        """,
            countQuery = """
        SELECT COUNT(*) FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            UPPER(ps.titre) LIKE UPPER('%' || ?1 || '%')
            OR UPPER(ps.description) LIKE UPPER('%' || ?1 || '%')
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(ps.mots_cles) AS mot
                WHERE UPPER(mot) LIKE UPPER('%' || ?1 || '%')
            )
        )
        """,
            nativeQuery = true)
    Page<PatientSpecificity> searchByTermPageable(String searchTerm, Pageable pageable);

    /**
     * Filtrage multi-critères (VERSION JPQL - PAS DE PROBLÈME)
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true
        AND (:categoryId IS NULL OR ps.categoryId = :categoryId)
        AND (:niveauAlerte IS NULL OR ps.niveauAlerte = :niveauAlerte)
        AND (:actif IS NULL OR ps.actif = :actif)
        """)
    Page<PatientSpecificity> findWithFilters(
            @Param("categoryId") String categoryId,
            @Param("niveauAlerte") String niveauAlerte,
            @Param("actif") Boolean actif,
            Pageable pageable);

    /**
     * Spécificités affectant une analyse donnée (VERSION CORRIGÉE - Sans conflit ?)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND (
            jsonb_exists(ps.analyses_contre_indiquees, ?1)
            OR jsonb_exists(ps.analyses_modifiees, ?1)
        )
        """, nativeQuery = true)
    List<PatientSpecificity> findAffectingAnalyse(String codeNabm);

    /**
     * Spécificités par priorité préleveur
     */
    Page<PatientSpecificity> findByPrioritePreleveurAndActifTrueOrderByTitre(Integer prioritePreleveur, Pageable pageable);

    /**
     * Spécificités nécessitant du temps supplémentaire
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND ps.tempsSupplementaireMinutes > 0
        ORDER BY ps.tempsSupplementaireMinutes DESC
        """)
    List<PatientSpecificity> findRequiringExtraTime();

    /**
     * Statistiques par niveau d'alerte
     */
    @Query("SELECT ps.niveauAlerte, COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true GROUP BY ps.niveauAlerte")
    List<Object[]> getSpecificitiesByNiveauAlerte();

    /**
     * Statistiques par catégorie
     */
    @Query("SELECT ps.categoryId, COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true GROUP BY ps.categoryId")
    List<Object[]> getSpecificitiesByCategory();

    /**
     * Recherche par mot-clé spécifique (VERSION CORRIGÉE - Sans conflit ?)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND jsonb_exists(ps.mots_cles, ?1)
        """, nativeQuery = true)
    List<PatientSpecificity> findByMotCle(String motCle);

    /**
     * Spécificités critiques (niveau d'alerte critique)
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND ps.niveauAlerte = 'CRITICAL'
        ORDER BY ps.prioritePreleveur DESC
        """)
    List<PatientSpecificity> findCriticalSpecificities();

    /**
     * Spécificités pour une catégorie donnée (version simple)
     */
    List<PatientSpecificity> findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(String categoryId);

    /**
     * Compter les spécificités actives
     */
    @Query("SELECT COUNT(ps) FROM PatientSpecificity ps WHERE ps.actif = true")
    long countActiveSpecificities();

    /**
     * Spécificités modifiant des analyses (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND ps.analyses_modifiees IS NOT NULL
        AND jsonb_array_length(ps.analyses_modifiees) > 0
        """, nativeQuery = true)
    List<PatientSpecificity> findWithAnalysesModifiees();

    /**
     * Spécificités contre-indiquant des analyses (VERSION CORRIGÉE POSTGRESQL)
     */
    @Query(value = """
        SELECT * FROM lims_referential.patient_specificities ps 
        WHERE ps.actif = true 
        AND ps.deleted_at IS NULL
        AND ps.analyses_contre_indiquees IS NOT NULL
        AND jsonb_array_length(ps.analyses_contre_indiquees) > 0
        """, nativeQuery = true)
    List<PatientSpecificity> findWithAnalysesContreIndiquees();
}
```

# lims-ref-service/src/main/java/com/lims/referential/repository/SpecificityCategoryRepository.java

```java
package com.lims.referential.repository;

import com.lims.referential.entity.SpecificityCategory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SpecificityCategoryRepository extends JpaRepository<SpecificityCategory, String> {

    /**
     * Recherche par nom
     */
    Optional<SpecificityCategory> findByNomAndActifTrue(String nom);

    /**
     * Toutes les catégories actives triées par ordre d'affichage
     */
    List<SpecificityCategory> findAllByActifTrueOrderByOrdreAffichage();

    /**
     * Catégories avec spécificités
     */
    @Query("""
        SELECT DISTINCT sc FROM SpecificityCategory sc 
        LEFT JOIN sc.specificities ps 
        WHERE sc.actif = true 
        AND ps.actif = true
        ORDER BY sc.ordreAffichage
        """)
    List<SpecificityCategory> findCategoriesWithActiveSpecificities();

    /**
     * Vérifier l'existence d'une catégorie
     */
    boolean existsByIdAndActifTrue(String id);
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/AnalyseService.java

```java
package com.lims.referential.service;

import com.lims.referential.enums.analyses.CategorieAnalyse;
import com.lims.referential.entity.Analyse;
import com.lims.referential.repository.AnalyseRepository;
import com.lims.referential.dto.response.PagedResponseDTO;
import com.lims.referential.dto.request.AnalyseRequestDTO;
import com.lims.referential.dto.response.AnalyseResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.AnalyseMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AnalyseService {

    private final AnalyseRepository analyseRepository;
    private final AnalyseMapper analyseMapper;

    /**
     * Récupère toutes les analyses avec pagination
     */
    @Cacheable(value = "analyses", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize + '-' + #pageable.sort.toString()")
    public PagedResponseDTO<AnalyseResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les analyses - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Analyse> analysePage = analyseRepository.findAll(pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Recherche une analyse par ID
     */
    @Cacheable(value = "analyses", key = "#id")
    public AnalyseResponseDTO findById(UUID id) {
        log.debug("Recherche de l'analyse avec l'ID: {}", id);

        Analyse analyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        return analyseMapper.toResponseDTO(analyse);
    }

    /**
     * Recherche par code NABM
     */
    @Cacheable(value = "analyses", key = "'nabm-' + #codeNabm")
    public AnalyseResponseDTO findByCodeNabm(String codeNabm) {
        log.debug("Recherche de l'analyse avec le code NABM: {}", codeNabm);

        Analyse analyse = analyseRepository.findByCodeNabmAndActifTrue(codeNabm)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec le code NABM: " + codeNabm));

        return analyseMapper.toResponseDTO(analyse);
    }

    /**
     * Recherche textuelle
     */
    @Cacheable(value = "analyses", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<AnalyseResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche d'analyses avec le terme: {}", searchTerm);

        Page<Analyse> analysePage = analyseRepository.searchByTerm(searchTerm, pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Auto-complétion
     */
    @Cacheable(value = "analyses", key = "'suggest-' + #prefix")
    public List<AnalyseResponseDTO> suggest(String prefix) {
        log.debug("Auto-complétion pour le préfixe: {}", prefix);

        Pageable pageable = PageRequest.of(0, 10, Sort.by("libelle"));
        List<Analyse> suggestions = analyseRepository.findSuggestions(prefix, pageable);

        return suggestions.stream()
                .map(analyseMapper::toResponseDTO)
                .toList();
    }

    /**
     * Filtrage multi-critères
     */
    public PagedResponseDTO<AnalyseResponseDTO> findWithFilters(
            CategorieAnalyse categorie, String sousCategorie, Boolean actif, Pageable pageable) {

        log.debug("Filtrage des analyses - catégorie: {}, sous-catégorie: {}, actif: {}",
                categorie, sousCategorie, actif);

        Page<Analyse> analysePage = analyseRepository.findWithFilters(categorie, sousCategorie, actif, pageable);
        List<AnalyseResponseDTO> analysesDTOs = analysePage.getContent()
                .stream()
                .map(analyseMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<AnalyseResponseDTO>builder()
                .content(analysesDTOs)
                .page(analysePage.getNumber())
                .size(analysePage.getSize())
                .totalElements(analysePage.getTotalElements())
                .totalPages(analysePage.getTotalPages())
                .first(analysePage.isFirst())
                .last(analysePage.isLast())
                .empty(analysePage.isEmpty())
                .build();
    }

    /**
     * Crée une nouvelle analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public AnalyseResponseDTO create(AnalyseRequestDTO requestDTO) {
        log.info("Création d'une nouvelle analyse avec le code NABM: {}", requestDTO.getCodeNabm());

        // Vérifier l'unicité du code NABM
        if (analyseRepository.findByCodeNabmAndActifTrue(requestDTO.getCodeNabm()).isPresent()) {
            throw new IllegalArgumentException("Une analyse existe déjà avec le code NABM: " + requestDTO.getCodeNabm());
        }

        Analyse analyse = analyseMapper.toEntity(requestDTO);
        Analyse savedAnalyse = analyseRepository.save(analyse);

        log.info("Analyse créée avec succès - ID: {}, Code NABM: {}", savedAnalyse.getId(), savedAnalyse.getCodeNabm());
        return analyseMapper.toResponseDTO(savedAnalyse);
    }

    /**
     * Met à jour une analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public AnalyseResponseDTO update(UUID id, AnalyseRequestDTO requestDTO) {
        log.info("Mise à jour de l'analyse avec l'ID: {}", id);

        Analyse existingAnalyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        // Vérifier l'unicité du code NABM si modifié
        if (!existingAnalyse.getCodeNabm().equals(requestDTO.getCodeNabm())) {
            if (analyseRepository.findByCodeNabmAndActifTrue(requestDTO.getCodeNabm()).isPresent()) {
                throw new IllegalArgumentException("Une analyse existe déjà avec le code NABM: " + requestDTO.getCodeNabm());
            }
        }

        analyseMapper.updateEntityFromDTO(requestDTO, existingAnalyse);
        Analyse updatedAnalyse = analyseRepository.save(existingAnalyse);

        log.info("Analyse mise à jour avec succès - ID: {}", updatedAnalyse.getId());
        return analyseMapper.toResponseDTO(updatedAnalyse);
    }

    /**
     * Suppression logique d'une analyse
     */
    @Transactional
    @CacheEvict(value = "analyses", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de l'analyse avec l'ID: {}", id);

        Analyse analyse = analyseRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Analyse non trouvée avec l'ID: " + id));

        analyse.markAsDeleted();
        analyseRepository.save(analyse);

        log.info("Analyse supprimée avec succès - ID: {}", id);
    }

    /**
     * Statistiques des analyses
     */
    @Cacheable(value = "analyses", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des analyses");

        long totalAnalyses = analyseRepository.countActiveAnalyses();
        List<Object[]> analysesByCategory = analyseRepository.getAnalysesByCategory();

        Map<String, Long> categoriesCount = analysesByCategory.stream()
                .collect(java.util.stream.Collectors.toMap(
                        obj -> obj[0].toString(),
                        obj -> (Long) obj[1]
                ));

        return Map.of(
                "totalAnalyses", totalAnalyses,
                "analysesByCategory", categoriesCount
        );
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/GeographiqueService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.Geographique;
import com.lims.referential.repository.GeographiqueRepository;
import com.lims.referential.dto.request.GeographiqueRequestDTO;
import com.lims.referential.dto.response.GeographiqueResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.GeographiqueMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class GeographiqueService {

    private final GeographiqueRepository geographiqueRepository;
    private final GeographiqueMapper geographiqueMapper;

    @Cacheable(value = "geographique", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<GeographiqueResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les données géographiques - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Geographique> geographiquePage = geographiqueRepository.findAll(pageable);
        List<GeographiqueResponseDTO> geographiquesDTOs = geographiquePage.getContent()
                .stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<GeographiqueResponseDTO>builder()
                .content(geographiquesDTOs)
                .page(geographiquePage.getNumber())
                .size(geographiquePage.getSize())
                .totalElements(geographiquePage.getTotalElements())
                .totalPages(geographiquePage.getTotalPages())
                .first(geographiquePage.isFirst())
                .last(geographiquePage.isLast())
                .empty(geographiquePage.isEmpty())
                .build();
    }

    @Cacheable(value = "geographique", key = "#id")
    public GeographiqueResponseDTO findById(UUID id) {
        log.debug("Recherche des données géographiques avec l'ID: {}", id);

        Geographique geographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        return geographiqueMapper.toResponseDTO(geographique);
    }

    @Cacheable(value = "geographique", key = "'cp-' + #codePostal")
    public List<GeographiqueResponseDTO> findByCodePostal(String codePostal) {
        log.debug("Recherche par code postal: {}", codePostal);

        List<Geographique> communes = geographiqueRepository.findByCodePostalAndActifTrue(codePostal);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'ville-' + #ville")
    public List<GeographiqueResponseDTO> findByVille(String ville) {
        log.debug("Recherche par ville: {}", ville);

        List<Geographique> communes = geographiqueRepository.findByNomCommuneContainingIgnoreCaseAndActifTrue(ville);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'dept-' + #departement")
    public List<GeographiqueResponseDTO> findByDepartement(String departement) {
        log.debug("Recherche par département: {}", departement);

        List<Geographique> communes = geographiqueRepository.findByDepartementAndActifTrue(departement);

        return communes.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "geographique", key = "'distance-' + #lat1 + '-' + #lon1 + '-' + #lat2 + '-' + #lon2")
    public Map<String, Object> calculateDistance(BigDecimal lat1, BigDecimal lon1, BigDecimal lat2, BigDecimal lon2) {
        log.debug("Calcul de distance entre ({}, {}) et ({}, {})", lat1, lon1, lat2, lon2);

        double distance = calculateHaversineDistance(lat1.doubleValue(), lon1.doubleValue(), lat2.doubleValue(), lon2.doubleValue());

        return Map.of(
                "distance_km", Math.round(distance * 100.0) / 100.0,
                "point1", Map.of("latitude", lat1, "longitude", lon1),
                "point2", Map.of("latitude", lat2, "longitude", lon2)
        );
    }

    public List<GeographiqueResponseDTO> findZonesDesserteByLaboratoire(UUID laboratoireId) {
        log.debug("Recherche des zones de desserte pour le laboratoire: {}", laboratoireId);

        List<Geographique> zones = geographiqueRepository.findZonesDesserteByLaboratoire(laboratoireId);

        return zones.stream()
                .map(geographiqueMapper::toResponseDTO)
                .toList();
    }

    public Map<String, Object> optimiserTournee(Map<String, Object> parametres) {
        log.debug("Optimisation de tournée avec paramètres: {}", parametres);

        // TODO: Implémenter l'algorithme d'optimisation de tournée
        // Pour l'instant, retourner une réponse basique

        return Map.of(
                "message", "Optimisation de tournée non encore implémentée",
                "parametres", parametres
        );
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public GeographiqueResponseDTO create(GeographiqueRequestDTO requestDTO) {
        log.info("Création de nouvelles données géographiques: {} - {}", requestDTO.getCodePostal(), requestDTO.getNomCommune());

        Geographique geographique = geographiqueMapper.toEntity(requestDTO);
        Geographique savedGeographique = geographiqueRepository.save(geographique);

        log.info("Données géographiques créées avec succès - ID: {}", savedGeographique.getId());
        return geographiqueMapper.toResponseDTO(savedGeographique);
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public GeographiqueResponseDTO update(UUID id, GeographiqueRequestDTO requestDTO) {
        log.info("Mise à jour des données géographiques avec l'ID: {}", id);

        Geographique existingGeographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        geographiqueMapper.updateEntityFromDTO(requestDTO, existingGeographique);
        Geographique updatedGeographique = geographiqueRepository.save(existingGeographique);

        log.info("Données géographiques mises à jour avec succès - ID: {}", updatedGeographique.getId());
        return geographiqueMapper.toResponseDTO(updatedGeographique);
    }

    @Transactional
    @CacheEvict(value = "geographique", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression des données géographiques avec l'ID: {}", id);

        Geographique geographique = geographiqueRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Données géographiques non trouvées avec l'ID: " + id));

        geographique.markAsDeleted();
        geographiqueRepository.save(geographique);

        log.info("Données géographiques supprimées avec succès - ID: {}", id);
    }

    @Cacheable(value = "geographique", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques géographiques");

        long totalCommunes = geographiqueRepository.count();
        long totalDepartements = geographiqueRepository.countDistinctDepartements();
        long totalRegions = geographiqueRepository.countDistinctRegions();

        return Map.of(
                "totalCommunes", totalCommunes,
                "totalDepartements", totalDepartements,
                "totalRegions", totalRegions
        );
    }

    // Méthode utilitaire pour le calcul de distance Haversine
    private double calculateHaversineDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Rayon de la Terre en kilomètres

        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);

        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        return R * c;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/LaboratoireService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.Laboratoire;
import com.lims.referential.repository.LaboratoireRepository;
import com.lims.referential.dto.request.LaboratoireRequestDTO;
import com.lims.referential.dto.response.LaboratoireResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.LaboratoireMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class LaboratoireService {

    private final LaboratoireRepository laboratoireRepository;
    private final LaboratoireMapper laboratoireMapper;

    @Cacheable(value = "laboratoires", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<LaboratoireResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de tous les laboratoires - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Laboratoire> laboratoirePage = laboratoireRepository.findAll(pageable);
        List<LaboratoireResponseDTO> laboratoiresDTOs = laboratoirePage.getContent()
                .stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<LaboratoireResponseDTO>builder()
                .content(laboratoiresDTOs)
                .page(laboratoirePage.getNumber())
                .size(laboratoirePage.getSize())
                .totalElements(laboratoirePage.getTotalElements())
                .totalPages(laboratoirePage.getTotalPages())
                .first(laboratoirePage.isFirst())
                .last(laboratoirePage.isLast())
                .empty(laboratoirePage.isEmpty())
                .build();
    }

    @Cacheable(value = "laboratoires", key = "#id")
    public LaboratoireResponseDTO findById(UUID id) {
        log.debug("Recherche du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        return laboratoireMapper.toResponseDTO(laboratoire);
    }

    @Cacheable(value = "laboratoires", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber")
    public PagedResponseDTO<LaboratoireResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de laboratoires avec le terme: {}", searchTerm);

        Page<Laboratoire> laboratoirePage = laboratoireRepository.searchByTerm(searchTerm, pageable);
        List<LaboratoireResponseDTO> laboratoiresDTOs = laboratoirePage.getContent()
                .stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<LaboratoireResponseDTO>builder()
                .content(laboratoiresDTOs)
                .page(laboratoirePage.getNumber())
                .size(laboratoirePage.getSize())
                .totalElements(laboratoirePage.getTotalElements())
                .totalPages(laboratoirePage.getTotalPages())
                .first(laboratoirePage.isFirst())
                .last(laboratoirePage.isLast())
                .empty(laboratoirePage.isEmpty())
                .build();
    }

    @Cacheable(value = "laboratoires", key = "'geoloc-' + #latitude + '-' + #longitude + '-' + #radius")
    public List<LaboratoireResponseDTO> searchByGeolocation(BigDecimal latitude, BigDecimal longitude, Integer radius) {
        log.debug("Recherche géographique - lat: {}, lon: {}, rayon: {}km", latitude, longitude, radius);

        List<Laboratoire> laboratoires = laboratoireRepository.findByGeolocation(latitude, longitude, radius);

        return laboratoires.stream()
                .map(laboratoireMapper::toResponseDTO)
                .toList();
    }

    @Cacheable(value = "laboratoires", key = "'analyses-' + #laboratoireId")
    public List<String> getAnalysesDisponibles(UUID laboratoireId) {
        log.debug("Récupération des analyses disponibles pour le laboratoire: {}", laboratoireId);

        Laboratoire laboratoire = laboratoireRepository.findById(laboratoireId)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + laboratoireId));

        return laboratoire.getAnalysesDisponibles();
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public LaboratoireResponseDTO create(LaboratoireRequestDTO requestDTO) {
        log.info("Création d'un nouveau laboratoire: {}", requestDTO.getNom());

        Laboratoire laboratoire = laboratoireMapper.toEntity(requestDTO);
        Laboratoire savedLaboratoire = laboratoireRepository.save(laboratoire);

        log.info("Laboratoire créé avec succès - ID: {}", savedLaboratoire.getId());
        return laboratoireMapper.toResponseDTO(savedLaboratoire);
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public LaboratoireResponseDTO update(UUID id, LaboratoireRequestDTO requestDTO) {
        log.info("Mise à jour du laboratoire avec l'ID: {}", id);

        Laboratoire existingLaboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        laboratoireMapper.updateEntityFromDTO(requestDTO, existingLaboratoire);
        Laboratoire updatedLaboratoire = laboratoireRepository.save(existingLaboratoire);

        log.info("Laboratoire mis à jour avec succès - ID: {}", updatedLaboratoire.getId());
        return laboratoireMapper.toResponseDTO(updatedLaboratoire);
    }

    @Transactional
    @CacheEvict(value = "laboratoires", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression du laboratoire avec l'ID: {}", id);

        Laboratoire laboratoire = laboratoireRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Laboratoire non trouvé avec l'ID: " + id));

        laboratoire.markAsDeleted();
        laboratoireRepository.save(laboratoire);

        log.info("Laboratoire supprimé avec succès - ID: {}", id);
    }

    @Cacheable(value = "laboratoires", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des laboratoires");

        long totalLaboratoires = laboratoireRepository.count();

        return Map.of(
                "totalLaboratoires", totalLaboratoires
        );
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/MedecinService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.Medecin;
import com.lims.referential.repository.MedecinRepository;
import com.lims.referential.dto.request.MedecinRequestDTO;
import com.lims.referential.dto.response.MedecinResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.MedecinMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MedecinService {

    private final MedecinRepository medecinRepository;
    private final MedecinMapper medecinMapper;

    @Cacheable(value = "medecins", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize + '-' + #pageable.sort.toString()")
    public PagedResponseDTO<MedecinResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de tous les médecins - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Medecin> medecinPage = medecinRepository.findAll(pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medecins", key = "#id")
    public MedecinResponseDTO findById(UUID id) {
        log.debug("Recherche du médecin avec l'ID: {}", id);

        Medecin medecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        return medecinMapper.toResponseDTO(medecin);
    }

    @Cacheable(value = "medecins", key = "'rpps-' + #numeroRpps")
    public MedecinResponseDTO findByNumeroRpps(String numeroRpps) {
        log.debug("Recherche du médecin avec le numéro RPPS: {}", numeroRpps);

        Medecin medecin = medecinRepository.findByNumeroRppsAndActifTrue(numeroRpps)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec le numéro RPPS: " + numeroRpps));

        return medecinMapper.toResponseDTO(medecin);
    }

    @Cacheable(value = "medecins", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<MedecinResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de médecins avec le terme: {}", searchTerm);

        Page<Medecin> medecinPage = medecinRepository.searchByTerm(searchTerm, pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medecins", key = "'suggest-' + #prefix")
    public List<MedecinResponseDTO> suggest(String prefix) {
        log.debug("Auto-complétion pour le préfixe: {}", prefix);

        Pageable pageable = PageRequest.of(0, 10, Sort.by("nom", "prenom"));
        List<Medecin> suggestions = medecinRepository.findSuggestions(prefix, pageable);

        return suggestions.stream()
                .map(medecinMapper::toResponseDTO)
                .toList();
    }

    public PagedResponseDTO<MedecinResponseDTO> findWithFilters(
            String specialite, String ville, String departement, Pageable pageable) {

        log.debug("Filtrage des médecins - spécialité: {}, ville: {}, département: {}",
                specialite, ville, departement);

        Page<Medecin> medecinPage = medecinRepository.findWithFilters(specialite, ville, departement, pageable);
        List<MedecinResponseDTO> medecinsDTOs = medecinPage.getContent()
                .stream()
                .map(medecinMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedecinResponseDTO>builder()
                .content(medecinsDTOs)
                .page(medecinPage.getNumber())
                .size(medecinPage.getSize())
                .totalElements(medecinPage.getTotalElements())
                .totalPages(medecinPage.getTotalPages())
                .first(medecinPage.isFirst())
                .last(medecinPage.isLast())
                .empty(medecinPage.isEmpty())
                .build();
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public MedecinResponseDTO create(MedecinRequestDTO requestDTO) {
        log.info("Création d'un nouveau médecin avec le numéro RPPS: {}", requestDTO.getNumeroRpps());

        if (medecinRepository.findByNumeroRppsAndActifTrue(requestDTO.getNumeroRpps()).isPresent()) {
            throw new IllegalArgumentException("Un médecin existe déjà avec le numéro RPPS: " + requestDTO.getNumeroRpps());
        }

        Medecin medecin = medecinMapper.toEntity(requestDTO);
        Medecin savedMedecin = medecinRepository.save(medecin);

        log.info("Médecin créé avec succès - ID: {}, RPPS: {}", savedMedecin.getId(), savedMedecin.getNumeroRpps());
        return medecinMapper.toResponseDTO(savedMedecin);
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public MedecinResponseDTO update(UUID id, MedecinRequestDTO requestDTO) {
        log.info("Mise à jour du médecin avec l'ID: {}", id);

        Medecin existingMedecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        if (!existingMedecin.getNumeroRpps().equals(requestDTO.getNumeroRpps())) {
            if (medecinRepository.findByNumeroRppsAndActifTrue(requestDTO.getNumeroRpps()).isPresent()) {
                throw new IllegalArgumentException("Un médecin existe déjà avec le numéro RPPS: " + requestDTO.getNumeroRpps());
            }
        }

        medecinMapper.updateEntityFromDTO(requestDTO, existingMedecin);
        Medecin updatedMedecin = medecinRepository.save(existingMedecin);

        log.info("Médecin mis à jour avec succès - ID: {}", updatedMedecin.getId());
        return medecinMapper.toResponseDTO(updatedMedecin);
    }

    @Transactional
    @CacheEvict(value = "medecins", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression du médecin avec l'ID: {}", id);

        Medecin medecin = medecinRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médecin non trouvé avec l'ID: " + id));

        medecin.markAsDeleted();
        medecinRepository.save(medecin);

        log.info("Médecin supprimé avec succès - ID: {}", id);
    }

    @Cacheable(value = "medecins", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des médecins");

        long totalMedecins = medecinRepository.count();

        return Map.of(
                "totalMedecins", totalMedecins
        );
    }
}


// PatientSpecificityService.java


// ValidationService.java


// CacheService.java

```

# lims-ref-service/src/main/java/com/lims/referential/service/MedicamentService.java

```java
package com.lims.referential.service;

import com.lims.referential.dto.request.CreateMedicamentRequest;
import com.lims.referential.dto.request.UpdateMedicamentRequest;
import com.lims.referential.dto.response.MedicamentResponse;
import com.lims.referential.entity.Medicament;
import com.lims.referential.mapper.MedicamentMapper;
import com.lims.referential.repository.MedicamentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Service pour la gestion des médicaments référentiels.
 * Utilise MedicamentMapper pour les conversions DTO/Entity.
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MedicamentService {

    private final MedicamentRepository medicamentRepository;
    private final MedicamentMapper medicamentMapper; // <- Utilisation du mapper

    /**
     * Récupère tous les médicaments actifs avec mise en cache
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments")
    public List<MedicamentResponse> findAllActifs() {
        log.debug("Récupération de tous les médicaments actifs");

        List<Medicament> medicaments = medicamentRepository.findByActifTrue();
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Récupère les médicaments avec pagination
     */
    @Transactional(readOnly = true)
    public Page<MedicamentResponse> findAll(Pageable pageable) {
        log.debug("Récupération des médicaments avec pagination: {}", pageable);

        Page<Medicament> medicaments = medicamentRepository.findAll(pageable);
        return medicaments.map(medicamentMapper::toResponse);
    }

    /**
     * Récupère un médicament par son ID
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "medicament", key = "#id")
    public MedicamentResponse findById(UUID id) {
        log.debug("Récupération du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        return medicamentMapper.toResponse(medicament);
    }

    /**
     * Récupère un médicament par son code CIS
     */
    @Transactional(readOnly = true)
    @Cacheable(value = "medicament", key = "#codeCis")
    public MedicamentResponse findByCodeCis(String codeCis) {
        log.debug("Récupération du médicament avec le code CIS: {}", codeCis);

        Medicament medicament = medicamentRepository.findByCodeCis(codeCis)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec le code CIS: " + codeCis));

        return medicamentMapper.toResponse(medicament);
    }

    /**
     * Recherche de médicaments par dénomination
     */
    @Transactional(readOnly = true)
    public List<MedicamentResponse> searchByDenomination(String denomination) {
        log.debug("Recherche de médicaments contenant: {}", denomination);

        List<Medicament> medicaments = medicamentRepository.findByDenominationContainingIgnoreCase(denomination);
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Crée un nouveau médicament
     */
    @CacheEvict(value = "medicaments", allEntries = true)
    public MedicamentResponse create(CreateMedicamentRequest request) {
        log.info("Création d'un nouveau médicament: {}", request.getCodeCis());

        // Vérifier que le code CIS n'existe pas déjà
        if (medicamentRepository.existsByCodeCis(request.getCodeCis())) {
            throw new IllegalArgumentException("Un médicament avec le code CIS " + request.getCodeCis() + " existe déjà");
        }

        // Conversion DTO -> Entity via le mapper
        Medicament medicament = medicamentMapper.toEntity(request);

        // Sauvegarde
        Medicament savedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament créé avec succès: {} (ID: {})", savedMedicament.getCodeCis(), savedMedicament.getId());

        // Conversion Entity -> DTO via le mapper
        return medicamentMapper.toResponse(savedMedicament);
    }

    /**
     * Met à jour un médicament existant
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public MedicamentResponse update(UUID id, UpdateMedicamentRequest request) {
        log.info("Mise à jour du médicament avec l'ID: {}", id);

        // Récupération du médicament existant
        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        // Mise à jour via le mapper
        medicamentMapper.updateEntityFromRequest(request, medicament);

        // Sauvegarde
        Medicament updatedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament mis à jour avec succès: {} (ID: {})", updatedMedicament.getCodeCis(), updatedMedicament.getId());

        // Conversion Entity -> DTO via le mapper
        return medicamentMapper.toResponse(updatedMedicament);
    }

    /**
     * Désactive un médicament (soft delete)
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public void desactiver(UUID id) {
        log.info("Désactivation du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        medicament.desactiver();
        medicamentRepository.save(medicament);

        log.info("Médicament désactivé: {} (ID: {})", medicament.getCodeCis(), medicament.getId());
    }

    /**
     * Réactive un médicament
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public MedicamentResponse reactiver(UUID id) {
        log.info("Réactivation du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id));

        medicament.reactiver();
        Medicament reactivatedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament réactivé: {} (ID: {})", reactivatedMedicament.getCodeCis(), reactivatedMedicament.getId());

        return medicamentMapper.toResponse(reactivatedMedicament);
    }

    /**
     * Supprime définitivement un médicament
     */
    @CacheEvict(value = {"medicaments", "medicament"}, allEntries = true)
    public void deleteDefinitivement(UUID id) {
        log.warn("Suppression définitive du médicament avec l'ID: {}", id);

        if (!medicamentRepository.existsById(id)) {
            throw new IllegalArgumentException("Médicament non trouvé avec l'ID: " + id);
        }

        medicamentRepository.deleteById(id);
        log.warn("Médicament supprimé définitivement (ID: {})", id);
    }

    /**
     * Récupère les médicaments remboursés
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments-rembourses")
    public List<MedicamentResponse> findMedicamentsRembourses() {
        log.debug("Récupération des médicaments remboursés");

        List<Medicament> medicaments = medicamentRepository.findByTauxRemboursementGreaterThan(0);
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Récupère les médicaments sous surveillance renforcée
     */
    @Transactional(readOnly = true)
    @Cacheable("medicaments-surveillance")
    public List<MedicamentResponse> findMedicamentsSurveillance() {
        log.debug("Récupération des médicaments sous surveillance renforcée");

        List<Medicament> medicaments = medicamentRepository.findBySurveillanceRenforceeTrue();
        return medicamentMapper.toResponseList(medicaments);
    }

    /**
     * Compte le nombre total de médicaments actifs
     */
    @Transactional(readOnly = true)
    public long countActifs() {
        return medicamentRepository.countByActifTrue();
    }

    /**
     * Vérifie si un médicament existe par son code CIS
     */
    @Transactional(readOnly = true)
    public boolean existsByCodeCis(String codeCis) {
        return medicamentRepository.existsByCodeCis(codeCis);
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/MutuelleService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.Mutuelle;
import com.lims.referential.repository.MutuelleRepository;
import com.lims.referential.dto.request.MutuelleRequestDTO;
import com.lims.referential.dto.response.MutuelleResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.MutuelleMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MutuelleService {

    private final MutuelleRepository mutuelleRepository;
    private final MutuelleMapper mutuelleMapper;

    @Cacheable(value = "mutuelles", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<MutuelleResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les mutuelles - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Mutuelle> mutuellePage = mutuelleRepository.findAll(pageable);
        List<MutuelleResponseDTO> mutuellesDTOs = mutuellePage.getContent()
                .stream()
                .map(mutuelleMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MutuelleResponseDTO>builder()
                .content(mutuellesDTOs)
                .page(mutuellePage.getNumber())
                .size(mutuellePage.getSize())
                .totalElements(mutuellePage.getTotalElements())
                .totalPages(mutuellePage.getTotalPages())
                .first(mutuellePage.isFirst())
                .last(mutuellePage.isLast())
                .empty(mutuellePage.isEmpty())
                .build();
    }

    @Cacheable(value = "mutuelles", key = "#id")
    public MutuelleResponseDTO findById(UUID id) {
        log.debug("Recherche de la mutuelle avec l'ID: {}", id);

        Mutuelle mutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        return mutuelleMapper.toResponseDTO(mutuelle);
    }

    @Cacheable(value = "mutuelles", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber")
    public PagedResponseDTO<MutuelleResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de mutuelles avec le terme: {}", searchTerm);

        Page<Mutuelle> mutuellePage = mutuelleRepository.searchByTerm(searchTerm, pageable);
        List<MutuelleResponseDTO> mutuellesDTOs = mutuellePage.getContent()
                .stream()
                .map(mutuelleMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MutuelleResponseDTO>builder()
                .content(mutuellesDTOs)
                .page(mutuellePage.getNumber())
                .size(mutuellePage.getSize())
                .totalElements(mutuellePage.getTotalElements())
                .totalPages(mutuellePage.getTotalPages())
                .first(mutuellePage.isFirst())
                .last(mutuellePage.isLast())
                .empty(mutuellePage.isEmpty())
                .build();
    }

    @Cacheable(value = "mutuelles", key = "'taux-' + #mutuelleId + '-' + #analyseCodes.hashCode()")
    public Map<String, Object> getTauxPriseEnCharge(UUID mutuelleId, List<String> analyseCodes) {
        log.debug("Calcul des taux de prise en charge pour la mutuelle: {} et les analyses: {}", mutuelleId, analyseCodes);

        Mutuelle mutuelle = mutuelleRepository.findById(mutuelleId)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + mutuelleId));

        BigDecimal tauxBase = mutuelle.getTauxBaseRemboursement();
        List<Mutuelle.AnalyseCouverture> analysesCouvertes = mutuelle.getAnalysesCouvertes();

        Map<String, BigDecimal> tauxParAnalyse = analyseCodes.stream()
                .collect(java.util.stream.Collectors.toMap(
                        code -> code,
                        code -> analysesCouvertes.stream()
                                .filter(ac -> ac.getCodeNabm().equals(code))
                                .findFirst()
                                .map(Mutuelle.AnalyseCouverture::getTauxRemboursement)
                                .orElse(tauxBase)
                ));

        return Map.of(
                "mutuelle", mutuelle.getNom(),
                "tauxBase", tauxBase,
                "tauxParAnalyse", tauxParAnalyse,
                "tiersPayant", mutuelle.getTiersPayant() != null ? mutuelle.getTiersPayant() : false
        );
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public MutuelleResponseDTO create(MutuelleRequestDTO requestDTO) {
        log.info("Création d'une nouvelle mutuelle: {}", requestDTO.getNom());

        Mutuelle mutuelle = mutuelleMapper.toEntity(requestDTO);
        Mutuelle savedMutuelle = mutuelleRepository.save(mutuelle);

        log.info("Mutuelle créée avec succès - ID: {}", savedMutuelle.getId());
        return mutuelleMapper.toResponseDTO(savedMutuelle);
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public MutuelleResponseDTO update(UUID id, MutuelleRequestDTO requestDTO) {
        log.info("Mise à jour de la mutuelle avec l'ID: {}", id);

        Mutuelle existingMutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        mutuelleMapper.updateEntityFromDTO(requestDTO, existingMutuelle);
        Mutuelle updatedMutuelle = mutuelleRepository.save(existingMutuelle);

        log.info("Mutuelle mise à jour avec succès - ID: {}", updatedMutuelle.getId());
        return mutuelleMapper.toResponseDTO(updatedMutuelle);
    }

    @Transactional
    @CacheEvict(value = "mutuelles", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de la mutuelle avec l'ID: {}", id);

        Mutuelle mutuelle = mutuelleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Mutuelle non trouvée avec l'ID: " + id));

        mutuelle.markAsDeleted();
        mutuelleRepository.save(mutuelle);

        log.info("Mutuelle supprimée avec succès - ID: {}", id);
    }

    @Cacheable(value = "mutuelles", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des mutuelles");

        long totalMutuelles = mutuelleRepository.count();

        return Map.of(
                "totalMutuelles", totalMutuelles
        );
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/PatientSpecificityService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.PatientSpecificity;
import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.repository.PatientSpecificityRepository;
import com.lims.referential.repository.SpecificityCategoryRepository;
import com.lims.referential.dto.request.PatientSpecificityRequestDTO;
import com.lims.referential.dto.response.PatientSpecificityResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.PatientSpecificityMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PatientSpecificityService {

    private final PatientSpecificityRepository patientSpecificityRepository;
    private final SpecificityCategoryRepository specificityCategoryRepository;
    private final PatientSpecificityMapper patientSpecificityMapper;

    @Cacheable(value = "patient-specificities", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<PatientSpecificityResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de toutes les spécificités patient - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository.findAll(pageable);
        List<PatientSpecificityResponseDTO> specificitiesDTOs = specificityPage.getContent()
                .stream()
                .map(patientSpecificityMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<PatientSpecificityResponseDTO>builder()
                .content(specificitiesDTOs)
                .page(specificityPage.getNumber())
                .size(specificityPage.getSize())
                .totalElements(specificityPage.getTotalElements())
                .totalPages(specificityPage.getTotalPages())
                .first(specificityPage.isFirst())
                .last(specificityPage.isLast())
                .empty(specificityPage.isEmpty())
                .build();
    }

    @Cacheable(value = "patient-specificities", key = "#id")
    public PatientSpecificityResponseDTO findById(UUID id) {
        log.debug("Recherche de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity specificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        return patientSpecificityMapper.toResponseDTO(specificity);
    }

    public PagedResponseDTO<PatientSpecificityResponseDTO> findWithFilters(
            String categorie, String niveauAlerte, Boolean actif, Pageable pageable) {

        log.debug("Filtrage des spécificités - catégorie: {}, niveau: {}, actif: {}",
                categorie, niveauAlerte, actif);

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository.findWithFilters(
                categorie, niveauAlerte, actif, pageable);
        List<PatientSpecificityResponseDTO> specificitiesDTOs = specificityPage.getContent()
                .stream()
                .map(patientSpecificityMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<PatientSpecificityResponseDTO>builder()
                .content(specificitiesDTOs)
                .page(specificityPage.getNumber())
                .size(specificityPage.getSize())
                .totalElements(specificityPage.getTotalElements())
                .totalPages(specificityPage.getTotalPages())
                .first(specificityPage.isFirst())
                .last(specificityPage.isLast())
                .empty(specificityPage.isEmpty())
                .build();
    }

    @Cacheable(value = "patient-specificities", key = "'instructions-' + #specificityId + '-' + #analyseCodes.hashCode()")
    public Map<String, Object> getInstructionsPreAnalytiques(UUID specificityId, List<String> analyseCodes) {
        log.debug("Récupération des instructions pré-analytiques pour la spécificité: {} et les analyses: {}",
                specificityId, analyseCodes);

        PatientSpecificity specificity = patientSpecificityRepository.findById(specificityId)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + specificityId));

        List<String> analysesContreIndiquees = specificity.getAnalysesContreIndiquees();
        List<String> analysesModifiees = specificity.getAnalysesModifiees();

        List<String> conflits = analyseCodes.stream()
                .filter(analysesContreIndiquees::contains)
                .toList();

        List<String> modifications = analyseCodes.stream()
                .filter(analysesModifiees::contains)
                .toList();

        return Map.of(
                "specificite", specificity.getTitre(),
                "niveauAlerte", specificity.getNiveauAlerte(),
                "instructionsPreleveur", specificity.getInstructionsPreleveur(),
                "instructionsTechnique", specificity.getInstructionsTechnique(),
                "analysesContreIndiquees", conflits,
                "analysesModifiees", modifications,
                "tempsSupplementaire", specificity.getTempsSupplementaireMinutes()
        );
    }

    @Cacheable(value = "patient-specificities", key = "'categories'")
    public List<Map<String, Object>> getCategoriesDynamiques() {
        log.debug("Récupération des catégories dynamiques");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(cat -> {
                    // ✅ SOLUTION PROPRE: Utiliser Map.of avec des types compatibles ou HashMap
                    Map<String, Object> categoryMap = new java.util.HashMap<>();
                    categoryMap.put("id", cat.getId());
                    categoryMap.put("nom", cat.getNom());
                    categoryMap.put("description", cat.getDescription());
                    categoryMap.put("couleur", cat.getCouleur());
                    categoryMap.put("icone", cat.getIcone());
                    return categoryMap;
                })
                .toList();
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public PatientSpecificityResponseDTO create(PatientSpecificityRequestDTO requestDTO) {
        log.info("Création d'une nouvelle spécificité patient: {}", requestDTO.getTitre());

        PatientSpecificity specificity = patientSpecificityMapper.toEntity(requestDTO);
        PatientSpecificity savedSpecificity = patientSpecificityRepository.save(specificity);

        log.info("Spécificité patient créée avec succès - ID: {}", savedSpecificity.getId());
        return patientSpecificityMapper.toResponseDTO(savedSpecificity);
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public PatientSpecificityResponseDTO update(UUID id, PatientSpecificityRequestDTO requestDTO) {
        log.info("Mise à jour de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity existingSpecificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        patientSpecificityMapper.updateEntityFromDTO(requestDTO, existingSpecificity);
        PatientSpecificity updatedSpecificity = patientSpecificityRepository.save(existingSpecificity);

        log.info("Spécificité patient mise à jour avec succès - ID: {}", updatedSpecificity.getId());
        return patientSpecificityMapper.toResponseDTO(updatedSpecificity);
    }

    @Transactional
    @CacheEvict(value = "patient-specificities", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression de la spécificité patient avec l'ID: {}", id);

        PatientSpecificity specificity = patientSpecificityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Spécificité patient non trouvée avec l'ID: " + id));

        specificity.markAsDeleted();
        patientSpecificityRepository.save(specificity);

        log.info("Spécificité patient supprimée avec succès - ID: {}", id);
    }

    // Méthodes à ajouter dans PatientSpecificityService.java

    /**
     * Récupère les spécificités groupées par catégorie
     * Utilisé par le composant PatientSituation
     */
    @Cacheable(value = "patient-specificities", key = "'grouped-by-category'")
    public Map<String, Object> getSpecificitiesGroupedByCategory() {
        log.debug("Récupération des spécificités groupées par catégorie");

        // Récupérer toutes les catégories actives
        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> categoriesData = new ArrayList<>();

        for (SpecificityCategory category : categories) {
            // Récupérer les spécificités de cette catégorie
            List<PatientSpecificity> specificities = patientSpecificityRepository
                    .findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(category.getId());

            Map<String, Object> categoryData = new HashMap<>();
            categoryData.put("id", category.getId());
            categoryData.put("nom", category.getNom());
            categoryData.put("description", category.getDescription());
            categoryData.put("couleur", category.getCouleur());
            categoryData.put("icone", category.getIcone());
            categoryData.put("ordreAffichage", category.getOrdreAffichage());

            // Convertir les spécificités en DTOs
            List<PatientSpecificityResponseDTO> specificitiesDTO = specificities.stream()
                    .map(patientSpecificityMapper::toResponseDTO)
                    .toList();

            categoryData.put("specificities", specificitiesDTO);
            categoryData.put("count", specificitiesDTO.size());

            categoriesData.add(categoryData);
        }

        result.put("categories", categoriesData);
        result.put("totalCategories", categoriesData.size());
        result.put("totalSpecificities", categoriesData.stream()
                .mapToInt(cat -> (Integer) cat.get("count"))
                .sum());

        return result;
    }

    /**
     * Récupère toutes les catégories actives (méthode de base)
     */
    @Cacheable(value = "patient-specificities", key = "'categories'")
    public List<Map<String, Object>> getCategories() {
        log.debug("Récupération de toutes les catégories actives");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(cat -> {
                    Map<String, Object> categoryMap = new HashMap<>();
                    categoryMap.put("id", cat.getId());
                    categoryMap.put("nom", cat.getNom());
                    categoryMap.put("description", cat.getDescription());
                    categoryMap.put("couleur", cat.getCouleur());
                    categoryMap.put("icone", cat.getIcone());
                    categoryMap.put("ordreAffichage", cat.getOrdreAffichage());
                    categoryMap.put("actif", cat.getActif());
                    return categoryMap;
                })
                .toList();
    }

    /**
     * Récupère les catégories avec leurs spécificités associées
     */
    @Cacheable(value = "patient-specificities", key = "'categories-with-specificities'")
    public List<Map<String, Object>> getCategoriesWithSpecificities() {
        log.debug("Récupération des catégories avec spécificités");

        return getCategories().stream()
                .map(category -> {
                    Map<String, Object> categoryMap = new HashMap<>();
                    categoryMap.put("id", category.get("id"));
                    categoryMap.put("nom", category.get("nom"));
                    categoryMap.put("description", category.get("description"));
                    categoryMap.put("couleur", category.get("couleur"));
                    categoryMap.put("icone", category.get("icone"));
                    categoryMap.put("ordreAffichage", category.get("ordreAffichage"));

                    // Récupérer les spécificités de cette catégorie
                    String categoryId = (String) category.get("id");
                    List<PatientSpecificity> specificities = patientSpecificityRepository
                            .findByCategoryIdAndActifTrueOrderByPrioritePreleveurDesc(categoryId);

                    List<PatientSpecificityResponseDTO> specificitiesDTO = specificities.stream()
                            .map(patientSpecificityMapper::toResponseDTO)
                            .toList();

                    categoryMap.put("specificities", specificitiesDTO);
                    return categoryMap;
                })
                .toList();
    }

    /**
     * Récupère les spécificités par catégorie avec pagination
     */
    public PagedResponseDTO<PatientSpecificityResponseDTO> findByCategory(String categoryId, Pageable pageable) {
        log.debug("Recherche des spécificités pour la catégorie: {}", categoryId);

        Page<PatientSpecificity> specificityPage = patientSpecificityRepository
                .findByCategoryIdAndActifTrue(categoryId, pageable);

        List<PatientSpecificityResponseDTO> specificitiesDTOs = specificityPage.getContent()
                .stream()
                .map(patientSpecificityMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<PatientSpecificityResponseDTO>builder()
                .content(specificitiesDTOs)
                .page(specificityPage.getNumber())
                .size(specificityPage.getSize())
                .totalElements(specificityPage.getTotalElements())
                .totalPages(specificityPage.getTotalPages())
                .first(specificityPage.isFirst())
                .last(specificityPage.isLast())
                .empty(specificityPage.isEmpty())
                .build();
    }

    /**
     * Récupère les statistiques sur les spécificités
     */
    @Cacheable(value = "patient-specificities", key = "'statistics'")
    public Map<String, Object> getStatistics() {
        log.debug("Génération des statistiques des spécificités");

        Map<String, Object> stats = new HashMap<>();

        // Statistiques générales
        long totalSpecificities = patientSpecificityRepository.countActiveSpecificities();
        stats.put("totalSpecificities", totalSpecificities);

        // Statistiques par niveau d'alerte
        List<Object[]> alerteStats = patientSpecificityRepository.getSpecificitiesByNiveauAlerte();
        Map<String, Long> alerteMap = alerteStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("byNiveauAlerte", alerteMap);

        // Statistiques par catégorie
        List<Object[]> categoryStats = patientSpecificityRepository.getSpecificitiesByCategory();
        Map<String, Long> categoryMap = categoryStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("byCategory", categoryMap);

        // Spécificités critiques
        List<PatientSpecificity> criticalSpecificities = patientSpecificityRepository.findCriticalSpecificities();
        stats.put("criticalCount", criticalSpecificities.size());

        // Spécificités nécessitant du temps supplémentaire
        List<PatientSpecificity> extraTimeSpecificities = patientSpecificityRepository.findRequiringExtraTime();
        stats.put("extraTimeCount", extraTimeSpecificities.size());

        return stats;
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/SpecificityCategoryService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.SpecificityCategory;
import com.lims.referential.repository.SpecificityCategoryRepository;
import com.lims.referential.repository.PatientSpecificityRepository;
import com.lims.referential.dto.response.SpecificityCategoryResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.SpecificityCategoryMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class SpecificityCategoryService {

    private final SpecificityCategoryRepository specificityCategoryRepository;
    private final PatientSpecificityRepository patientSpecificityRepository;
    private final SpecificityCategoryMapper specificityCategoryMapper;

    /**
     * Récupère toutes les catégories actives
     */
    @Cacheable(value = "specificity-categories", key = "'all-active'")
    public List<SpecificityCategoryResponseDTO> findAllActive() {
        log.debug("Récupération de toutes les catégories actives");

        List<SpecificityCategory> categories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();

        return categories.stream()
                .map(specificityCategoryMapper::toResponseDTO)
                .toList();
    }

    /**
     * Récupère une catégorie par son ID
     */
    @Cacheable(value = "specificity-categories", key = "#id")
    public SpecificityCategoryResponseDTO findById(String id) {
        log.debug("Recherche de la catégorie avec l'ID: {}", id);

        SpecificityCategory category = specificityCategoryRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Catégorie de spécificité non trouvée avec l'ID: " + id));

        return specificityCategoryMapper.toResponseDTO(category);
    }

    /**
     * Récupère les statistiques des catégories
     */
    @Cacheable(value = "specificity-categories", key = "'statistics'")
    public Map<String, Object> getStatistics() {
        log.debug("Génération des statistiques des catégories");

        Map<String, Object> stats = new HashMap<>();

        // Nombre total de catégories actives
        long totalCategories = specificityCategoryRepository.count();
        stats.put("totalCategories", totalCategories);

        // Statistiques par catégorie avec nombre de spécificités
        List<Object[]> categoryStats = patientSpecificityRepository.getSpecificitiesByCategory();
        Map<String, Long> categorySpecificityCount = categoryStats.stream()
                .collect(Collectors.toMap(
                        arr -> (String) arr[0],
                        arr -> (Long) arr[1]
                ));
        stats.put("specificitiesPerCategory", categorySpecificityCount);

        // Catégories les plus utilisées
        List<SpecificityCategory> allCategories = specificityCategoryRepository.findAllByActifTrueOrderByOrdreAffichage();
        List<Map<String, Object>> categoryDetails = allCategories.stream()
                .map(category -> {
                    Map<String, Object> details = new HashMap<>();
                    details.put("id", category.getId());
                    details.put("nom", category.getNom());
                    details.put("specificityCount", categorySpecificityCount.getOrDefault(category.getId(), 0L));
                    return details;
                })
                .sorted((a, b) -> Long.compare((Long) b.get("specificityCount"), (Long) a.get("specificityCount")))
                .toList();

        stats.put("categoryDetails", categoryDetails);

        return stats;
    }

    /**
     * Vérifie si une catégorie existe par son nom
     */
    public boolean existsByNom(String nom) {
        return specificityCategoryRepository.findByNomAndActifTrue(nom).isPresent();
    }
}
```

# lims-ref-service/src/main/java/com/lims/referential/service/ValidationService.java

```java
package com.lims.referential.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class ValidationService {

    private static final Pattern RPPS_PATTERN = Pattern.compile("^\\d{11}$");
    private static final Pattern NABM_PATTERN = Pattern.compile("^[A-Z]\\d{3}$");
    private static final Pattern CODE_POSTAL_PATTERN = Pattern.compile("^\\d{5}$");

    public Map<String, Object> validateRpps(String numeroRpps) {
        log.debug("Validation du numéro RPPS: {}", numeroRpps);

        boolean isValid = numeroRpps != null && RPPS_PATTERN.matcher(numeroRpps).matches();

        return Map.of(
                "numeroRpps", numeroRpps,
                "isValid", isValid,
                "format", "11 chiffres",
                "message", isValid ? "Numéro RPPS valide" : "Numéro RPPS invalide - doit contenir exactement 11 chiffres"
        );
    }

    public Map<String, Object> validateNabm(String codeNabm) {
        log.debug("Validation du code NABM: {}", codeNabm);

        boolean isValid = codeNabm != null && NABM_PATTERN.matcher(codeNabm).matches();

        return Map.of(
                "codeNabm", codeNabm,
                "isValid", isValid,
                "format", "1 lettre + 3 chiffres",
                "message", isValid ? "Code NABM valide" : "Code NABM invalide - format attendu: 1 lettre suivie de 3 chiffres (ex: B145)"
        );
    }

    public Map<String, Object> validateCodePostal(String codePostal, String ville) {
        log.debug("Validation du code postal: {} pour la ville: {}", codePostal, ville);

        boolean isValidFormat = codePostal != null && CODE_POSTAL_PATTERN.matcher(codePostal).matches();

        // TODO: Ajouter une validation avec la base géographique
        boolean isValidWithVille = isValidFormat; // Pour l'instant, seulement le format

        return Map.of(
                "codePostal", codePostal,
                "ville", ville,
                "isValidFormat", isValidFormat,
                "isValidWithVille", isValidWithVille,
                "format", "5 chiffres",
                "message", isValidFormat ? "Code postal valide" : "Code postal invalide - doit contenir exactement 5 chiffres"
        );
    }
}
```

# lims-ref-service/src/main/java/com/lims/ReferentialServiceApplication.java

```java
package com.lims;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Application principale du service référentiel LIMS
 *
 * Responsabilités :
 * - Gestion des analyses biologiques avec codes NABM
 * - Annuaire des médecins de France avec RPPS
 * - Répertoire des laboratoires partenaires
 * - Base des médicaments avec interactions
 * - Organismes complémentaires (mutuelles)
 * - Données géographiques et codes postaux
 * - Spécificités patient impactant les prélèvements
 */
@SpringBootApplication
@EnableCaching
@EnableTransactionManagement
public class ReferentialServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ReferentialServiceApplication.class, args);
    }
}
```

# lims-ref-service/src/main/resources/application.yml

```yml
server:
  port: 8093

spring:
  application:
    name: lims-ref-service
  profiles:
    active: development

  # Database configuration
  datasource:
    url: jdbc:postgresql://localhost:5432/lims_db
    username: lims_user
    password: dev_password_123
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: LIMS-Ref-Pool
      maximum-pool-size: 10
      minimum-idle: 2
      connection-timeout: 20000
      idle-timeout: 300000
      max-lifetime: 1200000

  # JPA Configuration
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true

# Configuration JWT spécifique au service référentiel
lims:
  jwt:
    secret: "G9/BrPDMezKO3cxercRPm7OtvRjWGOeONQCk7AjB6s+pttEuco8xcUEE6dT2IHNHix9aNk4i+c1N8CaTTp84WxCfZMCC/UVJABajwU4ToymMJ/9gT3uxMK5PqrJcCHNi2cUo3P9k+ZaBCqvqwcDZv6kY7mdaz6G5VmcWAU8+4OgZVZEssNvY2kTInV2Sz4JZzp4/N8aWGf6ml3C+q4I8l0Yk9qImvqnAeMX83Rxp3R+yLk2LvCuaYx1lEkSbkM2NbsN1W8ebtZwxMC0CpeLY57V7DocrjvK7v/pjHHUu27qad1JgLBhmoNy4LZX1rqLSKdYvjGQqQd8SU4vP311d9fY8rv47DLKjSPKkee4XTtrfTfH1fh3mnPjYl2NoZjCzr7KAHB3lKpk56rUlmXYbqqExOlDGmnXOrnCL5JRj3LWgwvw6sR73/CGsigxkZvks00QF48cSfJPgFT+TdZ4FyAxc9vC+MG5FDdSjG+wCgmJ/UYQ9MOdLhNGs2itMpf3mN/z81/JYbbDxrNWPah56Ybr8Y4DUykgfJLMgiK/nwME5/qwjzkfRpjEMBRaZbIJPy7N+NfdgIolVjdNj6eBNUHLlrerV2G5FcEkHTsYrTIFrhxxAI3gE3KI92pBPBXxKohXrvVt4nupaj9onnzfP/y5s5kQkNUomVQYMIbyUKGU="

  # Configuration spécifique aux données de référence
  referential:
    cache:
      enabled: true
      ttl-minutes: 30

    # Types de données de référence gérées
    data-types:
      - ANALYSES
      - LABORATOIRES
      - NOMENCLATURES
      - TARIFS
      - UNITES_MESURE

# Logging
logging:
  level:
    com.lims: DEBUG
    org.springframework.security: INFO
    org.springframework.security.oauth2: DEBUG
    org.hibernate.SQL: WARN
    root: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

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
    urls-primary-name: "Referential Service API"
    display-request-duration: true
    show-extensions: true
    show-common-extensions: true
```

# lims-ref-service/src/test/java/com/lims/integration/ReferentialControllerTest.java

```java
package com.lims.integration;

import com.lims.util.JwtTestUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests d'intégration pour valider l'authentification JWT dans le service référentiel.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ReferentialControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldAllowAccessWithValidAdminToken() throws Exception {
        String validToken = JwtTestUtil.generateValidAdminToken("admin@lims.com");

        mockMvc.perform(get("/api/v1/referential/health")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("lims-ref-service"))
                .andExpect(jsonPath("$.user").value("admin@lims.com"))
                .andExpect(jsonPath("$.realm").value("lims-admin"));
    }

    @Test
    void shouldRejectAccessWithoutToken() throws Exception {
        mockMvc.perform(get("/api/v1/referential/health"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectAccessWithInvalidRealm() throws Exception {
        String invalidToken = JwtTestUtil.generateInvalidRealmToken("patient@lims.com");

        mockMvc.perform(get("/api/v1/referential/health")
                        .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectAccessWithInvalidUserType() throws Exception {
        String invalidToken = JwtTestUtil.generateInvalidUserTypeToken("staff@lims.com");

        mockMvc.perform(get("/api/v1/referential/health")
                        .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectExpiredToken() throws Exception {
        String expiredToken = JwtTestUtil.generateExpiredToken("admin@lims.com");

        mockMvc.perform(get("/api/v1/referential/health")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldAllowAdminToCRUDAnalyses() throws Exception {
        String validToken = JwtTestUtil.generateValidAdminToken("admin@lims.com");

        // Test GET analyses
        mockMvc.perform(get("/api/v1/referential/analyses")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].code").exists())
                .andExpect(jsonPath("$[0].nom").exists());

        // Test POST nouvelle analyse
        String newAnalyse = """
                {
                    "code": "TEST001",
                    "nom": "Test Analysis",
                    "prix": 29.99
                }
                """;

        mockMvc.perform(post("/api/v1/referential/analyses")
                        .header("Authorization", "Bearer " + validToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(newAnalyse))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Analyse créée avec succès"));
    }

    @Test
    void shouldReturnAdminInfoForValidToken() throws Exception {
        String validToken = JwtTestUtil.generateValidAdminToken("super.admin@lims.com");

        mockMvc.perform(get("/api/v1/referential/admin-info")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("super.admin@lims.com"))
                .andExpect(jsonPath("$.realm").value("lims-admin"))
                .andExpect(jsonPath("$.userType").value("ADMIN"))
                .andExpect(jsonPath("$.authorities").isArray())
                .andExpect(jsonPath("$.permissions").exists())
                .andExpect(jsonPath("$.adminLevel").value("SUPER_ADMIN"));
    }
}

```

# lims-ref-service/src/test/java/com/lims/util/JwtTestUtil.java

```java
package com.lims.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

/**
 * Utilitaire pour générer des tokens JWT de test pour le service référentiel.
 */
public class JwtTestUtil {

    private static final String TEST_SECRET = "lims-super-secret-key-for-development-only-change-in-production";

    /**
     * Génère un token JWT admin valide pour les tests
     */
    public static String generateValidAdminToken(String username) {
        return generateToken(username, "lims-admin", "ADMIN",
                Map.of("permissions", "SYSTEM_WIDE", "admin_level", "SUPER_ADMIN"));
    }

    /**
     * Génère un token JWT avec un realm invalide (pour tester le rejet)
     */
    public static String generateInvalidRealmToken(String username) {
        return generateToken(username, "lims-patient", "PATIENT",
                Map.of("patient_id", "12345"));
    }

    /**
     * Génère un token JWT avec un user_type invalide (pour tester le rejet)
     */
    public static String generateInvalidUserTypeToken(String username) {
        return generateToken(username, "lims-admin", "STAFF",
                Map.of("laboratory_id", "lab123"));
    }

    /**
     * Génère un token JWT expiré (pour tester le rejet)
     */
    public static String generateExpiredToken(String username) {
        SecretKeySpec secretKey = new SecretKeySpec(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );

        Instant now = Instant.now();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now.minus(2, ChronoUnit.HOURS)))
                .setExpiration(Date.from(now.minus(1, ChronoUnit.HOURS))) // Expiré depuis 1h
                .claim("realm", "lims-admin")
                .claim("user_type", "ADMIN")
                .claim("email", username + "@lims.com")
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    private static String generateToken(String username, String realm, String userType,
                                        Map<String, Object> additionalClaims) {
        SecretKeySpec secretKey = new SecretKeySpec(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );

        Instant now = Instant.now();

        var builder = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .claim("realm", realm)
                .claim("user_type", userType)
                .claim("email", username + "@lims.com");

        // Ajouter les claims supplémentaires
        additionalClaims.forEach(builder::claim);

        return builder.signWith(secretKey, SignatureAlgorithm.HS512).compact();
    }
}

```

# lims-ref-service/structure.md

```md
src/main/java/com/lims/referential/
├── ReferentialServiceApplication.java
├── config/
│   ├── DatabaseConfig.java
│   ├── RedisConfig.java
│   ├── CacheConfig.java
│   └── OpenAPIConfig.java
├── controller/
│   ├── AnalyseController.java
│   ├── MedecinController.java
│   ├── LaboratoireController.java
│   ├── MedicamentController.java
│   ├── MutuelleController.java
│   ├── GeographiqueController.java
│   ├── PatientSpecificityController.java
│   ├── ValidationController.java
│   └── CacheController.java
├── service/
│   ├── AnalyseService.java
│   ├── MedecinService.java
│   ├── LaboratoireService.java
│   ├── MedicamentService.java
│   ├── MutuelleService.java
│   ├── GeographiqueService.java
│   ├── PatientSpecificityService.java
│   ├── ValidationService.java
│   └── CacheService.java
├── repository/
│   ├── AnalyseRepository.java
│   ├── MedecinRepository.java
│   ├── LaboratoireRepository.java
│   ├── MedicamentRepository.java
│   ├── MutuelleRepository.java
│   ├── GeographiqueRepository.java
│   └── PatientSpecificityRepository.java
├── entity/
│   ├── BaseEntity.java
│   ├── Analyse.java
│   ├── Medecin.java
│   ├── Laboratoire.java
│   ├── Medicament.java
│   ├── Mutuelle.java
│   ├── CodePostal.java
│   ├── PatientSpecificity.java
│   └── SpecificityCategory.java
├── dto/
│   ├── request/
│   │   ├── AnalyseRequestDTO.java
│   │   ├── MedecinRequestDTO.java
│   │   ├── LaboratoireRequestDTO.java
│   │   ├── MedicamentRequestDTO.java
│   │   ├── MutuelleRequestDTO.java
│   │   └── PatientSpecificityRequestDTO.java
│   ├── response/
│   │   ├── AnalyseResponseDTO.java
│   │   ├── MedecinResponseDTO.java
│   │   ├── LaboratoireResponseDTO.java
│   │   ├── MedicamentResponseDTO.java
│   │   ├── MutuelleResponseDTO.java
│   │   └── PatientSpecificityResponseDTO.java
│   └── common/
│       ├── PagedResponseDTO.java
│       ├── ErrorResponseDTO.java
│       └── ApiResponseDTO.java
├── enums/
│   ├── analyses/
│   │   ├── CategorieAnalyse.java
│   │   ├── NiveauUrgence.java
│   │   ├── TypeTube.java
│   │   └── CouleurTube.java
│   ├── medecins/
│   │   ├── Civilite.java
│   │   ├── SpecialiteMedicale.java
│   │   └── SecteurConventionnement.java
│   ├── laboratoires/
│   │   └── TypeLaboratoire.java
│   ├── medicaments/
│   │   └── ClasseTherapeutique.java
│   └── common/
│       ├── UniteTemps.java
│       └── TypeOrganisme.java
├── mapper/
│   ├── AnalyseMapper.java
│   ├── MedecinMapper.java
│   ├── LaboratoireMapper.java
│   ├── MedicamentMapper.java
│   ├── MutuelleMapper.java
│   └── PatientSpecificityMapper.java
├── exception/
│   ├── ResourceNotFoundException.java
│   ├── ValidationException.java
│   ├── DuplicateResourceException.java
│   └── GlobalExceptionHandler.java
└── util/
├── CacheConstants.java
├── ValidationUtils.java
├── GeographiqueUtils.java
└── CsvExportUtils.java
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
        <module>lims-ref-service</module>
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

# TODO.md

```md
TODO:

- [ ] Rajouter un ref de situation 
- [ ] Créer un patient (prendre en compte la situation du patient)
- [ ] Mettre à jour un patient (json patch) (prendre en compte la situation du patient)
- [ ] Mettre à jour la situation du patient
- [ ] initier service référentiel (avec analyses)
- [ ] initier service document avec minio (pour upload des mutuelles et ordonnances)
- [ ] initier service parcours/dossier (pour y rajouter les ordonnances, analyses, réponses aux conditions pré-analytics)

```

