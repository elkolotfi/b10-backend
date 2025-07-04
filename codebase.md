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
    url: jdbc:postgresql://localhost:5432/lims_auth
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
        issuer-uri: http://localhost:8080/realms/lims-admin
        jwk-set-uri: http://localhost:8080/realms/lims-admin/protocol/openid-connect/certs

# Logging
logging:
  level:
    com.lims.auth: DEBUG
    org.springframework.security: DEBUG
    org.hibernate.SQL: DEBUG
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
    </properties>

    <modules>
        <module>lims-auth-service</module>
        <module>lims-laboratory-service</module>
        <module>lims-auth-service</module>
        <module>lims-laboratory-service</module>
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
        </dependencies>
    </dependencyManagement>

    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-maven-plugin</artifactId>
                    <version>${spring.boot.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>3.11.0</version>
                    <configuration>
                        <source>21</source>
                        <target>21</target>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>
</project>
```

