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