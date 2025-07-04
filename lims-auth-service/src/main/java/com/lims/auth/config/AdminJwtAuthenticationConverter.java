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
