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