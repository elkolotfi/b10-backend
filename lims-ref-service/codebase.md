# pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.lims</groupId>
    <artifactId>lims-referential-service</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>LIMS Referential Service</name>
    <description>Service référentiel pour le système LIMS - Gestion des données métier</description>

    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring.boot.version>3.2.1</spring.boot.version>
        <mapstruct.version>1.6.3</mapstruct.version>
        <testcontainers.version>1.19.3</testcontainers.version>
        <springdoc.version>2.2.0</springdoc.version>
        <lombok.version>1.18.30</lombok.version>
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
            <artifactId>spring-boot-starter-cache</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- Database -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- Documentation -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>${springdoc.version}</version>
        </dependency>

        <!-- Utilities -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>${lombok.version}</version>
            <scope>provided</scope>
        </dependency>

        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>${mapstruct.version}</version>
        </dependency>

        <!-- CSV Processing -->
        <dependency>
            <groupId>com.opencsv</groupId>
            <artifactId>opencsv</artifactId>
            <version>5.9</version>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
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

    <profiles>
        <profile>
            <id>docker</id>
            <properties>
                <spring.profiles.active>docker</spring.profiles.active>
            </properties>
        </profile>
    </profiles>
</project>
```

# src/main/java/com/lims/referential/config/CacheConfig.java

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

# src/main/java/com/lims/referential/config/DatabaseConfig.java

```java
// DatabaseConfig.java
package com.lims.referential.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(basePackages = "com.lims.referential.domain")
@EnableJpaRepositories(basePackages = "com.lims.referential.infrastructure.persistence")
public class DatabaseConfig {
}
```

# src/main/java/com/lims/referential/config/MultiRealmJwtDecoder.java

```java
package com.lims.referential.config;

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

# src/main/java/com/lims/referential/config/OpenAPIConfig.java

```java
package com.lims.referential.config;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfig {

    @Value("${server.port:9093}")
    private int serverPort;

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LIMS Referential Service API")
                        .description("Service référentiel pour le système LIMS - Gestion des données métier : analyses biologiques, médecins, laboratoires, médicaments, mutuelles, géographique et spécificités patient")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Équipe LIMS")
                                .email("contact@lims.fr"))
                        .license(new License()
                                .name("Propriétaire")
                                .url("https://lims.fr/license")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Serveur de développement local"),
                        new Server()
                                .url("http://ref.lims.local")
                                .description("Serveur de développement Docker")
                ));
    }
}

```

# src/main/java/com/lims/referential/config/PatientJwtAuthenticationConverter.java

```java
package com.lims.referential.config;

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

# src/main/java/com/lims/referential/config/RedisConfig.java

```java
package com.lims.referential.config;

import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public CacheManager cacheManager(RedisConnectionFactory connectionFactory) {
        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(
                        org.springframework.data.redis.cache.RedisCacheConfiguration.defaultCacheConfig()
                                .entryTtl(Duration.ofHours(1))
                                .serializeKeysWith(org.springframework.data.redis.serializer.RedisSerializationContext.SerializationPair
                                        .fromSerializer(new StringRedisSerializer()))
                                .serializeValuesWith(org.springframework.data.redis.serializer.RedisSerializationContext.SerializationPair
                                        .fromSerializer(new GenericJackson2JsonRedisSerializer()))
                )
                .build();
    }
}

```

# src/main/java/com/lims/referential/config/SecurityConfig.java

```java
package com.lims.referential.config;

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
                        .requestMatchers("/api/v1/**").permitAll()
                        // .authenticated()

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

# src/main/java/com/lims/referential/config/SimpleHmacJwtDecoder.java

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

# src/main/java/com/lims/referential/config/ValidationConfig.java

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

# src/main/java/com/lims/referential/controller/AnalyseController.java

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

# src/main/java/com/lims/referential/dto/common/ApiResponseDTO.java

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

# src/main/java/com/lims/referential/dto/common/CacheStatsDTO.java

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

# src/main/java/com/lims/referential/dto/common/DistanceCalculationDTO.java

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

# src/main/java/com/lims/referential/dto/common/ErrorResponseDTO.java

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

# src/main/java/com/lims/referential/dto/common/ExportRequestDTO.java

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

# src/main/java/com/lims/referential/dto/common/ImportResultDTO.java

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

# src/main/java/com/lims/referential/dto/common/InteractionCheckDTO.java

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

# src/main/java/com/lims/referential/dto/common/PagedResponseDTO.java

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

# src/main/java/com/lims/referential/dto/common/SearchCriteriaDTO.java

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

# src/main/java/com/lims/referential/dto/common/StatisticsDTO.java

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

# src/main/java/com/lims/referential/dto/common/SuggestionDTO.java

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

# src/main/java/com/lims/referential/dto/common/ValidationResultDTO.java

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

# src/main/java/com/lims/referential/dto/request/AnalyseRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/BulkOperationRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/CachePreloadRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/GeographiqueRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/GeolocationSearchRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/LaboratoireRequestDTO.java

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
public class LaboratoireRequestDTO {

    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Size(max = 255, message = "Le nom commercial ne peut pas dépasser 255 caractères")
    private String nomCommercial;

    @Size(max = 14, message = "Le SIRET ne peut pas dépasser 14 caractères")
    private String siret;

    // Adresse
    @NotBlank(message = "L'adresse est obligatoire")
    @Size(max = 255, message = "L'adresse ne peut pas dépasser 255 caractères")
    private String adresseLigne1;

    @Size(max = 255, message = "L'adresse ligne 2 ne peut pas dépasser 255 caractères")
    private String adresseLigne2;

    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10, message = "Le code postal ne peut pas dépasser 10 caractères")
    private String codePostal;

    @NotBlank(message = "La ville est obligatoire")
    @Size(max = 100, message = "La ville ne peut pas dépasser 100 caractères")
    private String ville;

    @Size(max = 100, message = "Le département ne peut pas dépasser 100 caractères")
    private String departement;

    @Size(max = 100, message = "La région ne peut pas dépasser 100 caractères")
    private String region;

    @Builder.Default
    @Size(max = 50, message = "Le pays ne peut pas dépasser 50 caractères")
    private String pays = "France";

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Contact
    @Valid
    private ContactLaboratoireRequestDTO contact;

    // Informations pratiques
    @Valid
    private InformationsPratiquesRequestDTO informationsPratiques;

    // Capacités techniques
    @Valid
    private CapacitesTechniquesRequestDTO capacitesTechniques;

    // Zone de desserte
    @Builder.Default
    private Integer zoneDesserteKm = 50;

    @Builder.Default
    private Boolean prelevementDomicile = false;

    @Builder.Default
    private Boolean actif = true;

    @Data
    @Builder
    public static class ContactLaboratoireRequestDTO {
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
    public static class InformationsPratiquesRequestDTO {
        private Map<String, List<String>> horairesOuverture;

        @Builder.Default
        private Boolean parkingDisponible = false;

        @Builder.Default
        private Boolean accesHandicapes = false;

        @Size(max = 255)
        private String transportPublic;
    }

    @Data
    @Builder
    public static class CapacitesTechniquesRequestDTO {
        private List<String> analysesDisponibles; // codes NABM
        private List<String> specialitesTechniques;
        private List<String> equipementsSpeciaux;
    }
}
```

# src/main/java/com/lims/referential/dto/request/MedecinRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/MedicamentRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/MutuelleRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/PatientSpecificityRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/SpecificityCategoryRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/SynchronisationRequestDTO.java

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

# src/main/java/com/lims/referential/dto/request/TourneeOptimisationRequestDTO.java

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

# src/main/java/com/lims/referential/dto/response/AnalyseInteractionResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/AnalyseResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/BulkOperationResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/ErrorResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/GeographiqueResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/LaboratoireResponseDTO.java

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
public class LaboratoireResponseDTO {

    private UUID id;
    private String nom;
    private String nomCommercial;
    private String siret;

    // Adresse
    private String adresseLigne1;
    private String adresseLigne2;
    private String codePostal;
    private String ville;
    private String departement;
    private String region;
    private String pays;

    // Géolocalisation
    private BigDecimal latitude;
    private BigDecimal longitude;

    // Contact
    private ContactLaboratoireResponseDTO contact;

    // Informations pratiques
    private InformationsPratiquesResponseDTO informationsPratiques;

    // Capacités techniques
    private CapacitesTechniquesResponseDTO capacitesTechniques;

    // Zone de desserte
    private Integer zoneDesserteKm;
    private Boolean prelevementDomicile;
    private Boolean actif;

    // Métadonnées
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer version;

    @Data
    @Builder
    public static class ContactLaboratoireResponseDTO {
        private String telephone;
        private String fax;
        private String email;
        private String siteWeb;
    }

    @Data
    @Builder
    public static class InformationsPratiquesResponseDTO {
        private Map<String, List<String>> horairesOuverture;
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

# src/main/java/com/lims/referential/dto/response/MedecinResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/MedicamentResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/MutuelleResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/PagedResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/PatientSpecificityResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/SpecificityCategoryResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/SynchronisationResponseDTO.java

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

# src/main/java/com/lims/referential/dto/response/TourneeOptimisationResponseDTO.java

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

# src/main/java/com/lims/referential/entity/Analyse.java

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

# src/main/java/com/lims/referential/entity/BaseEntity.java

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

# src/main/java/com/lims/referential/entity/Geographique.java

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

# src/main/java/com/lims/referential/entity/Laboratoire.java

```java
// Laboratoire.java
package com.lims.referential.entity;

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
@Table(name = "laboratoires", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Laboratoire extends BaseEntity {

    @Column(name = "nom", nullable = false)
    @NotBlank(message = "Le nom est obligatoire")
    @Size(max = 255, message = "Le nom ne peut pas dépasser 255 caractères")
    private String nom;

    @Column(name = "nom_commercial")
    @Size(max = 255)
    private String nomCommercial;

    @Column(name = "siret", length = 14)
    @Size(max = 14)
    private String siret;

    // Adresse
    @Column(name = "adresse_ligne1", nullable = false)
    @NotBlank(message = "L'adresse est obligatoire")
    @Size(max = 255)
    private String adresseLigne1;

    @Column(name = "adresse_ligne2")
    @Size(max = 255)
    private String adresseLigne2;

    @Column(name = "code_postal", nullable = false, length = 10)
    @NotBlank(message = "Le code postal est obligatoire")
    @Size(max = 10)
    private String codePostal;

    @Column(name = "ville", nullable = false, length = 100)
    @NotBlank(message = "La ville est obligatoire")
    @Size(max = 100)
    private String ville;

    @Column(name = "departement", length = 100)
    @Size(max = 100)
    private String departement;

    @Column(name = "region", length = 100)
    @Size(max = 100)
    private String region;

    @Builder.Default
    @Column(name = "pays", length = 50)
    private String pays = "France";

    // Géolocalisation
    @Column(name = "latitude", precision = 10, scale = 8)
    private BigDecimal latitude;

    @Column(name = "longitude", precision = 11, scale = 8)
    private BigDecimal longitude;

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

    // Informations pratiques
    @Column(name = "horaires_ouverture", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, List<String>> horairesOuverture;

    @Builder.Default
    @Column(name = "parking_disponible")
    private Boolean parkingDisponible = false;

    @Builder.Default
    @Column(name = "acces_handicapes")
    private Boolean accesHandicapes = false;

    @Column(name = "transport_public")
    @Size(max = 255)
    private String transportPublic;

    // Capacités techniques
    @Column(name = "analyses_disponibles", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesDisponibles;

    @Column(name = "specialites_techniques", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> specialitesTechniques;

    @Column(name = "equipements_speciaux", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> equipementsSpeciaux;

    // Zone de desserte
    @Builder.Default
    @Column(name = "zone_desserte_km")
    private Integer zoneDesserteKm = 50;

    @Builder.Default
    @Column(name = "prelevement_domicile")
    private Boolean prelevementDomicile = false;

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}
```

# src/main/java/com/lims/referential/entity/Medecin.java

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

# src/main/java/com/lims/referential/entity/Medicament.java

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
@Table(name = "medicaments", schema = "lims_referential")
@Where(clause = "deleted_at IS NULL")
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class Medicament extends BaseEntity {

    @Column(name = "nom_commercial", nullable = false)
    @NotBlank(message = "Le nom commercial est obligatoire")
    @Size(max = 255)
    private String nomCommercial;

    @Column(name = "dci", nullable = false)
    @NotBlank(message = "La DCI est obligatoire")
    @Size(max = 255)
    private String dci; // Dénomination Commune Internationale

    @Column(name = "code_cip", length = 13)
    @Size(max = 13)
    private String codeCip;

    // Classification
    @Column(name = "classe_therapeutique", length = 100)
    @Size(max = 100)
    private String classeTherapeutique;

    @Column(name = "sous_classe", length = 100)
    @Size(max = 100)
    private String sousClasse;

    @Column(name = "forme_pharmaceutique", length = 100)
    @Size(max = 100)
    private String formePharmaceutique;

    @Column(name = "dosage", length = 100)
    @Size(max = 100)
    private String dosage;

    @Column(name = "voie_administration", length = 100)
    @Size(max = 100)
    private String voieAdministration;

    // Interactions avec analyses
    @Column(name = "analyses_impactees", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> analysesImpactees; // Array des codes NABM

    @Column(name = "type_interaction", length = 50)
    @Size(max = 50)
    private String typeInteraction; // interference, faux_positif, faux_negatif

    @Column(name = "niveau_criticite", length = 20)
    @Size(max = 20)
    private String niveauCriticite; // faible, modere, eleve, critique

    // Délais pré-analytiques
    @Builder.Default
    @Column(name = "arret_requis")
    private Boolean arretRequis = false;

    @Builder.Default
    @Column(name = "delai_arret_heures")
    private Integer delaiArretHeures = 0;

    @Column(name = "instructions_arret", columnDefinition = "TEXT")
    private String instructionsArret;

    // Informations complémentaires
    @Column(name = "principe_actif")
    @Size(max = 255)
    private String principeActif;

    @Column(name = "laboratoire_fabricant")
    @Size(max = 255)
    private String laboratoireFabricant;

    @Column(name = "statut_commercialisation", length = 50)
    @Size(max = 50)
    private String statutCommercialisation; // commercialise, arrete, suspendu

    @Builder.Default
    @Column(name = "actif", nullable = false)
    private Boolean actif = true;
}
```

# src/main/java/com/lims/referential/entity/Mutuelle.java

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

# src/main/java/com/lims/referential/entity/PatientSpecificity.java

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

# src/main/java/com/lims/referential/entity/SpecificityCategory.java

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

# src/main/java/com/lims/referential/enums/analyses/CategorieAnalyse.java

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

# src/main/java/com/lims/referential/enums/analyses/Civilite.java

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

# src/main/java/com/lims/referential/enums/analyses/CouleurTube.java

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

# src/main/java/com/lims/referential/enums/analyses/NiveauUrgence.java

```java
package com.lims.referential.enums.analyses;

public enum NiveauUrgence {
    NORMAL,
    PRIORITAIRE,
    URGENT,
    VITAL
}

```

# src/main/java/com/lims/referential/enums/analyses/PositionPatient.java

```java
package com.lims.referential.enums.analyses;

public enum PositionPatient {
    DEBOUT,
    ASSIS,
    ALLONGE,
    INDIFFERENT
}

```

# src/main/java/com/lims/referential/enums/analyses/TemperatureConservation.java

```java
package com.lims.referential.enums.analyses;

public enum TemperatureConservation {
    TEMPERATURE_AMBIANTE,
    REFRIGERE_2_8,
    CONGELE_MOINS_20,
    CONGELE_MOINS_80
}

```

# src/main/java/com/lims/referential/enums/analyses/TypeTube.java

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

# src/main/java/com/lims/referential/enums/common/UniteTemps.java

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

# src/main/java/com/lims/referential/enums/laboratoires/SpecialiteTechnique.java

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

# src/main/java/com/lims/referential/enums/laboratoires/TypeLaboratoire.java

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

# src/main/java/com/lims/referential/enums/medecins/ModeExercice.java

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

# src/main/java/com/lims/referential/enums/medecins/SecteurConventionnement.java

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

# src/main/java/com/lims/referential/enums/medecins/SpecialiteMedicale.java

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

# src/main/java/com/lims/referential/enums/medicaments/ClasseTherapeutique.java

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

# src/main/java/com/lims/referential/enums/medicaments/FormePharmaceutique.java

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

# src/main/java/com/lims/referential/enums/medicaments/NiveauCriticite.java

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

# src/main/java/com/lims/referential/enums/medicaments/StatutCommercialisation.java

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

# src/main/java/com/lims/referential/enums/medicaments/TypeInteraction.java

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

# src/main/java/com/lims/referential/enums/medicaments/VoieAdministration.java

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

# src/main/java/com/lims/referential/enums/mutuelles/ModeTransmission.java

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

# src/main/java/com/lims/referential/enums/mutuelles/TypeOrganisme.java

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

# src/main/java/com/lims/referential/enums/patient/NiveauAlerte.java

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

# src/main/java/com/lims/referential/enums/patient/PrioritePreleveur.java

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

# src/main/java/com/lims/referential/exception/GlobalExceptionHandler.java

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

# src/main/java/com/lims/referential/exception/ResourceNotFoundException.java

```java
package com.lims.referential.exception;

/**
 * Exception levée quand une ressource demandée n'est pas trouvée
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

# src/main/java/com/lims/referential/mapper/AnalyseMapper.java

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

# src/main/java/com/lims/referential/mapper/GeographiqueMapper.java

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

# src/main/java/com/lims/referential/mapper/LaboratoireMapper.java

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
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
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
     * Met à jour une entité existante avec les données du DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "deletedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntityFromDTO(MedicamentRequestDTO requestDTO, @MappingTarget Medicament medicament);
}

```

# src/main/java/com/lims/referential/mapper/MedecinMapper.java

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

# src/main/java/com/lims/referential/mapper/MutuelleMapper.java

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

# src/main/java/com/lims/referential/mapper/PatientSpecificityMapper.java

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

# src/main/java/com/lims/referential/mapper/SpecificityCategoryMapper.java

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

# src/main/java/com/lims/referential/repository/AnalyseRepository.java

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

# src/main/java/com/lims/referential/repository/GeographiqueRepository.java

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
        AND JSON_CONTAINS(g.laboratoiresZone, JSON_QUOTE(:laboratoireId))
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

# src/main/java/com/lims/referential/repository/LaboratoireRepository.java

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
import java.util.UUID;

@Repository
public interface LaboratoireRepository extends JpaRepository<Laboratoire, UUID> {

    /**
     * Recherche par ville
     */
    Page<Laboratoire> findByVilleAndActifTrue(String ville, Pageable pageable);

    /**
     * Recherche par code postal
     */
    Page<Laboratoire> findByCodePostalAndActifTrue(String codePostal, Pageable pageable);

    /**
     * Recherche par département
     */
    Page<Laboratoire> findByDepartementAndActifTrue(String departement, Pageable pageable);

    /**
     * Recherche textuelle
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true 
        AND (UPPER(l.nom) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(l.nomCommercial) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(l.ville) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(l.siret) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY l.nom
        """)
    Page<Laboratoire> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Recherche géographique dans un rayon donné
     */
    @Query(value = """
        SELECT l.*, 
               (6371 * ACOS(
                   COS(RADIANS(:latitude)) * COS(RADIANS(l.latitude)) * 
                   COS(RADIANS(l.longitude) - RADIANS(:longitude)) + 
                   SIN(RADIANS(:latitude)) * SIN(RADIANS(l.latitude))
               )) AS distance
        FROM lims_referential.laboratoires l 
        WHERE l.actif = true 
        AND l.latitude IS NOT NULL 
        AND l.longitude IS NOT NULL
        AND (6371 * ACOS(
                COS(RADIANS(:latitude)) * COS(RADIANS(l.latitude)) * 
                COS(RADIANS(l.longitude) - RADIANS(:longitude)) + 
                SIN(RADIANS(:latitude)) * SIN(RADIANS(l.latitude))
            )) <= :radiusKm
        ORDER BY distance
        """, nativeQuery = true)
    List<Laboratoire> findByGeolocation(
            @Param("latitude") BigDecimal latitude,
            @Param("longitude") BigDecimal longitude,
            @Param("radiusKm") Integer radiusKm);

    /**
     * Recherche des laboratoires proposant une analyse spécifique
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true 
        AND JSON_CONTAINS(l.analysesDisponibles, JSON_QUOTE(:codeNabm))
        """)
    List<Laboratoire> findByAnalyseDisponible(@Param("codeNabm") String codeNabm);

    /**
     * Recherche des laboratoires avec prélèvement à domicile
     */
    Page<Laboratoire> findByPrelevementDomicileAndActifTrue(Boolean prelevementDomicile, Pageable pageable);

    /**
     * Statistiques par région
     */
    @Query("SELECT l.region, COUNT(l) FROM Laboratoire l WHERE l.actif = true GROUP BY l.region")
    List<Object[]> countByRegion();

    /**
     * Laboratoires dans une zone de desserte
     */
    @Query("""
        SELECT l FROM Laboratoire l 
        WHERE l.actif = true 
        AND l.zoneDesserteKm >= :distanceKm
        """)
    List<Laboratoire> findByZoneDesserteMinimum(@Param("distanceKm") Integer distanceKm);
}
```

# src/main/java/com/lims/referential/repository/MedecinRepository.java

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

# src/main/java/com/lims/referential/repository/MedicamentRepository.java

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

@Repository
public interface MedicamentRepository extends JpaRepository<Medicament, UUID> {

    /**
     * Recherche par nom commercial
     */
    Optional<Medicament> findByNomCommercialAndActifTrue(String nomCommercial);

    /**
     * Recherche par DCI
     */
    Page<Medicament> findByDciContainingIgnoreCaseAndActifTrue(String dci, Pageable pageable);

    /**
     * Recherche par code CIP
     */
    Optional<Medicament> findByCodeCipAndActifTrue(String codeCip);

    /**
     * Recherche par classe thérapeutique
     */
    Page<Medicament> findByClasseTherapeutiqueAndActifTrue(String classeTherapeutique, Pageable pageable);

    /**
     * Recherche textuelle
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE m.actif = true 
        AND (UPPER(m.nomCommercial) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.dci) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.principeActif) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(m.codeCip) LIKE UPPER(CONCAT('%', :searchTerm, '%')))
        ORDER BY 
            CASE WHEN UPPER(m.nomCommercial) = UPPER(:searchTerm) THEN 1
                 WHEN UPPER(m.dci) = UPPER(:searchTerm) THEN 2
                 WHEN UPPER(m.nomCommercial) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 3
                 WHEN UPPER(m.dci) LIKE UPPER(CONCAT(:searchTerm, '%')) THEN 4
                 ELSE 5 END,
            m.nomCommercial
        """)
    Page<Medicament> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Recherche des médicaments avec interactions sur une analyse
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE m.actif = true 
        AND JSON_CONTAINS(m.analysesImpactees, JSON_QUOTE(:codeNabm))
        """)
    List<Medicament> findByAnalyseImpactee(@Param("codeNabm") String codeNabm);

    /**
     * Recherche par niveau de criticité
     */
    Page<Medicament> findByNiveauCriticiteAndActifTrue(String niveauCriticite, Pageable pageable);

    /**
     * Médicaments nécessitant un arrêt
     */
    Page<Medicament> findByArretRequisAndActifTrue(Boolean arretRequis, Pageable pageable);

    /**
     * Recherche par statut de commercialisation
     */
    Page<Medicament> findByStatutCommercialisationAndActifTrue(String statut, Pageable pageable);

    /**
     * Statistiques par classe thérapeutique
     */
    @Query("SELECT m.classeTherapeutique, COUNT(m) FROM Medicament m WHERE m.actif = true GROUP BY m.classeTherapeutique")
    List<Object[]> countByClasseTherapeutique();

    /**
     * Statistiques par niveau de criticité
     */
    @Query("SELECT m.niveauCriticite, COUNT(m) FROM Medicament m WHERE m.actif = true GROUP BY m.niveauCriticite")
    List<Object[]> countByNiveauCriticite();

    /**
     * Médicaments avec délai d'arrêt supérieur à une valeur
     */
    @Query("""
        SELECT m FROM Medicament m 
        WHERE m.actif = true 
        AND m.arretRequis = true 
        AND m.delaiArretHeures >= :delaiMinimum
        ORDER BY m.delaiArretHeures DESC
        """)
    List<Medicament> findByDelaiArretMinimum(@Param("delaiMinimum") Integer delaiMinimum);
}
```

# src/main/java/com/lims/referential/repository/MutuelleRepository.java

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
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND JSON_EXTRACT(m.codesFacturation, '$.tiersPayant') = true
        """)
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
    @Query("""
        SELECT m FROM Mutuelle m 
        WHERE m.actif = true 
        AND (JSON_CONTAINS(JSON_EXTRACT(m.analysesCouvertes, '$[*].codeNabm'), JSON_QUOTE(:codeNabm))
             OR NOT JSON_CONTAINS(m.analysesExclues, JSON_QUOTE(:codeNabm)))
        """)
    List<Mutuelle> findCoveringAnalyse(@Param("codeNabm") String codeNabm);

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

# src/main/java/com/lims/referential/repository/PatientSpecificityRepository.java

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
     * Recherche textuelle
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND (UPPER(ps.titre) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR UPPER(ps.description) LIKE UPPER(CONCAT('%', :searchTerm, '%'))
             OR JSON_SEARCH(ps.motsCles, 'one', CONCAT('%', :searchTerm, '%')) IS NOT NULL)
        ORDER BY ps.prioritePreleveur DESC, ps.titre
        """)
    Page<PatientSpecificity> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    /**
     * Filtrage multi-critères
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
     * Spécificités affectant une analyse donnée
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND (JSON_CONTAINS(ps.analysesContreIndiquees, JSON_QUOTE(:codeNabm))
             OR JSON_CONTAINS(ps.analysesModifiees, JSON_QUOTE(:codeNabm)))
        """)
    List<PatientSpecificity> findAffectingAnalyse(@Param("codeNabm") String codeNabm);

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
     * Recherche par mots-clés
     */
    @Query("""
        SELECT ps FROM PatientSpecificity ps 
        WHERE ps.actif = true 
        AND JSON_SEARCH(ps.motsCles, 'one', :motCle) IS NOT NULL
        """)
    List<PatientSpecificity> findByMotCle(@Param("motCle") String motCle);
}
```

# src/main/java/com/lims/referential/repository/SpecificityCategoryRepository.java

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

# src/main/java/com/lims/referential/service/AnalyseService.java

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

# src/main/java/com/lims/referential/service/CacheService.java

```java
package com.lims.referential.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class CacheService {

    private final CacheManager cacheManager;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final List<String> CACHE_NAMES = List.of(
            "analyses", "medecins", "laboratoires", "medicaments",
            "mutuelles", "geographique", "patient-specificities"
    );

    public void clearAllCaches() {
        log.info("Vidage de tous les caches");

        CACHE_NAMES.forEach(cacheName -> {
            var cache = cacheManager.getCache(cacheName);
            if (cache != null) {
                cache.clear();
                log.debug("Cache '{}' vidé", cacheName);
            }
        });
    }

    public void clearCacheByDomain(String domain) {
        log.info("Vidage du cache pour le domaine: {}", domain);

        var cache = cacheManager.getCache(domain);
        if (cache != null) {
            cache.clear();
            log.debug("Cache '{}' vidé", domain);
        } else {
            log.warn("Cache '{}' non trouvé", domain);
        }
    }

    public Map<String, Object> getCacheStatistics() {
        log.debug("Récupération des statistiques du cache");

        Map<String, Object> stats = new HashMap<>();

        CACHE_NAMES.forEach(cacheName -> {
            var cache = cacheManager.getCache(cacheName);
            if (cache != null) {
                // Statistiques basiques pour chaque cache
                Map<String, Object> cacheStats = Map.of(
                        "name", cacheName,
                        "nativeCache", cache.getNativeCache().getClass().getSimpleName()
                );
                stats.put(cacheName, cacheStats);
            }
        });

        return Map.of(
                "caches", stats,
                "totalCaches", CACHE_NAMES.size()
        );
    }

    public void preloadCaches(List<String> domaines, boolean forcer) {
        log.info("Préchargement des caches pour les domaines: {}, forcer: {}", domaines, forcer);

        if (forcer) {
            domaines.forEach(this::clearCacheByDomain);
        }

        // TODO: Implémenter le préchargement spécifique par domaine
        // Pour l'instant, log seulement
        log.info("Préchargement des caches terminé pour: {}", domaines);
    }
}
```

# src/main/java/com/lims/referential/service/GeographiqueService.java

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

# src/main/java/com/lims/referential/service/LaboratoireService.java

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

# src/main/java/com/lims/referential/service/MedecinService.java

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

# src/main/java/com/lims/referential/service/MedicamentService.java

```java
package com.lims.referential.service;

import com.lims.referential.entity.Medicament;
import com.lims.referential.repository.MedicamentRepository;
import com.lims.referential.dto.request.MedicamentRequestDTO;
import com.lims.referential.dto.response.MedicamentResponseDTO;
import com.lims.referential.dto.common.PagedResponseDTO;
import com.lims.referential.exception.ResourceNotFoundException;
import com.lims.referential.mapper.MedicamentMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class MedicamentService {

    private final MedicamentRepository medicamentRepository;
    private final MedicamentMapper medicamentMapper;

    @Cacheable(value = "medicaments", key = "'all-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    public PagedResponseDTO<MedicamentResponseDTO> findAll(Pageable pageable) {
        log.debug("Récupération de tous les médicaments - page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());

        Page<Medicament> medicamentPage = medicamentRepository.findAll(pageable);
        List<MedicamentResponseDTO> medicamentsDTOs = medicamentPage.getContent()
                .stream()
                .map(medicamentMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedicamentResponseDTO>builder()
                .content(medicamentsDTOs)
                .page(medicamentPage.getNumber())
                .size(medicamentPage.getSize())
                .totalElements(medicamentPage.getTotalElements())
                .totalPages(medicamentPage.getTotalPages())
                .first(medicamentPage.isFirst())
                .last(medicamentPage.isLast())
                .empty(medicamentPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medicaments", key = "#id")
    public MedicamentResponseDTO findById(UUID id) {
        log.debug("Recherche du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médicament non trouvé avec l'ID: " + id));

        return medicamentMapper.toResponseDTO(medicament);
    }

    @Cacheable(value = "medicaments", key = "'search-' + #searchTerm + '-' + #pageable.pageNumber")
    public PagedResponseDTO<MedicamentResponseDTO> search(String searchTerm, Pageable pageable) {
        log.debug("Recherche de médicaments avec le terme: {}", searchTerm);

        Page<Medicament> medicamentPage = medicamentRepository.searchByTerm(searchTerm, pageable);
        List<MedicamentResponseDTO> medicamentsDTOs = medicamentPage.getContent()
                .stream()
                .map(medicamentMapper::toResponseDTO)
                .toList();

        return PagedResponseDTO.<MedicamentResponseDTO>builder()
                .content(medicamentsDTOs)
                .page(medicamentPage.getNumber())
                .size(medicamentPage.getSize())
                .totalElements(medicamentPage.getTotalElements())
                .totalPages(medicamentPage.getTotalPages())
                .first(medicamentPage.isFirst())
                .last(medicamentPage.isLast())
                .empty(medicamentPage.isEmpty())
                .build();
    }

    @Cacheable(value = "medicaments", key = "'interactions-' + #medicamentId + '-' + #analyseCodes.hashCode()")
    public Map<String, Object> checkInteractions(UUID medicamentId, List<String> analyseCodes) {
        log.debug("Vérification des interactions pour le médicament: {} avec les analyses: {}", medicamentId, analyseCodes);

        Medicament medicament = medicamentRepository.findById(medicamentId)
                .orElseThrow(() -> new ResourceNotFoundException("Médicament non trouvé avec l'ID: " + medicamentId));

        List<String> analysesImpactees = medicament.getAnalysesImpactees();
        List<String> interactionsDetectees = analyseCodes.stream()
                .filter(analysesImpactees::contains)
                .toList();

        return Map.of(
                "medicament", medicament.getNomCommercial(),
                "interactionsDetectees", interactionsDetectees,
                "niveauCriticite", medicament.getNiveauCriticite(),
                "arretRequis", medicament.getArretRequis(),
                "delaiArret", medicament.getDelaiArretHeures()
        );
    }

    @Transactional
    @CacheEvict(value = "medicaments", allEntries = true)
    public MedicamentResponseDTO create(MedicamentRequestDTO requestDTO) {
        log.info("Création d'un nouveau médicament: {}", requestDTO.getNomCommercial());

        Medicament medicament = medicamentMapper.toEntity(requestDTO);
        Medicament savedMedicament = medicamentRepository.save(medicament);

        log.info("Médicament créé avec succès - ID: {}", savedMedicament.getId());
        return medicamentMapper.toResponseDTO(savedMedicament);
    }

    @Transactional
    @CacheEvict(value = "medicaments", allEntries = true)
    public MedicamentResponseDTO update(UUID id, MedicamentRequestDTO requestDTO) {
        log.info("Mise à jour du médicament avec l'ID: {}", id);

        Medicament existingMedicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médicament non trouvé avec l'ID: " + id));

        medicamentMapper.updateEntityFromDTO(requestDTO, existingMedicament);
        Medicament updatedMedicament = medicamentRepository.save(existingMedicament);

        log.info("Médicament mis à jour avec succès - ID: {}", updatedMedicament.getId());
        return medicamentMapper.toResponseDTO(updatedMedicament);
    }

    @Transactional
    @CacheEvict(value = "medicaments", allEntries = true)
    public void delete(UUID id) {
        log.info("Suppression du médicament avec l'ID: {}", id);

        Medicament medicament = medicamentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Médicament non trouvé avec l'ID: " + id));

        medicament.markAsDeleted();
        medicamentRepository.save(medicament);

        log.info("Médicament supprimé avec succès - ID: {}", id);
    }

    @Cacheable(value = "medicaments", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des médicaments");

        long totalMedicaments = medicamentRepository.count();

        return Map.of(
                "totalMedicaments", totalMedicaments
        );
    }
}
```

# src/main/java/com/lims/referential/service/MutuelleService.java

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

# src/main/java/com/lims/referential/service/PatientSpecificityService.java

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

import java.util.List;
import java.util.Map;
import java.util.UUID;

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
                .map(cat -> Map.of(
                        "id", cat.getId(),
                        "nom", cat.getNom(),
                        "description", cat.getDescription(),
                        "couleur", cat.getCouleur(),
                        "icone", cat.getIcone()
                ))
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

    @Cacheable(value = "patient-specificities", key = "'stats'")
    public Map<String, Object> getStatistics() {
        log.debug("Récupération des statistiques des spécificités patient");

        long totalSpecificites = patientSpecificityRepository.count();
        List<Object[]> specificitesByNiveau = patientSpecificityRepository.getSpecificitiesByNiveauAlerte();

        Map<String, Long> niveauxCount = specificitesByNiveau.stream()
                .collect(java.util.stream.Collectors.toMap(
                        obj -> obj[0].toString(),
                        obj -> (Long) obj[1]
                ));

        return Map.of(
                "totalSpecificites", totalSpecificites,
                "specificitesByNiveau", niveauxCount
        );
    }
}
```

# src/main/java/com/lims/referential/service/ValidationService.java

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

# src/main/java/com/lims/ReferentialServiceApplication.java

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
@EnableJpaAuditing
@EnableCaching
@EnableTransactionManagement
public class ReferentialServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ReferentialServiceApplication.class, args);
    }
}
```

# src/main/resources/application.yml

```yml
server:
  port: 8093

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
      default_schema: lims_referential
    show-sql: false  # true en développement
    open-in-view: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        default_schema: lims_referential
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

# structure.md

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

