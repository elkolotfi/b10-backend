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
