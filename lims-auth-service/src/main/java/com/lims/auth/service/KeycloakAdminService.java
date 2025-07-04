package com.lims.auth.service;

import com.lims.auth.exception.AuthenticationException;
import com.lims.auth.exception.KeycloakException;
import com.lims.auth.config.LimsAuthProperties;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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