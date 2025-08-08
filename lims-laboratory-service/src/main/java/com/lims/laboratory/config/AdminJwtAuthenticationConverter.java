package com.lims.laboratory.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.List;

/**
 * Convertisseur d'authentification JWT spécialisé pour les admins.
 * Extrait les rôles admin et configure l'authentification.
 */
@Slf4j
public class AdminJwtAuthenticationConverter extends JwtAuthenticationConverter {

    public AdminJwtAuthenticationConverter() {
        this.setJwtGrantedAuthoritiesConverter(this::extractAuthorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Pour le service référentiel, tous les utilisateurs valides sont admins
        return List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("ROLE_ADMIN_LAB")
        );
    }
}