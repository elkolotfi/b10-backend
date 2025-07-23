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
