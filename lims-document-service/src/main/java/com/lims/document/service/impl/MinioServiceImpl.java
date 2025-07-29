package com.lims.document.service.impl;

import com.lims.document.exception.DocumentUploadException;
import com.lims.document.service.MinioService;
import io.minio.*;
import io.minio.http.Method;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class MinioServiceImpl implements MinioService {

    private final MinioClient minioClient;

    @Override
    public void uploadFile(String bucketName, String objectKey, InputStream inputStream,
                           long contentLength, String contentType) {
        try {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectKey)
                            .stream(inputStream, contentLength, -1)
                            .contentType(contentType)
                            .build()
            );

            log.debug("Fichier uploadé avec succès: {}/{}", bucketName, objectKey);

        } catch (Exception e) {
            log.error("Erreur lors de l'upload vers MinIO: {}", e.getMessage(), e);
            throw new DocumentUploadException("Erreur d'upload vers le stockage", e);
        }
    }

    @Override
    public byte[] downloadFile(String bucketName, String objectKey) {
        try (InputStream stream = minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(bucketName)
                        .object(objectKey)
                        .build());
             ByteArrayOutputStream result = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int length;
            while ((length = stream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }

            log.debug("Fichier téléchargé avec succès: {}/{}", bucketName, objectKey);
            return result.toByteArray();

        } catch (Exception e) {
            log.error("Erreur lors du téléchargement depuis MinIO: {}", e.getMessage(), e);
            throw new DocumentUploadException("Erreur de téléchargement depuis le stockage", e);
        }
    }

    @Override
    public String generatePresignedUrl(String bucketName, String objectKey, int expirationMinutes) {
        try {
            return minioClient.getPresignedObjectUrl(
                    GetPresignedObjectUrlArgs.builder()
                            .method(Method.GET)
                            .bucket(bucketName)
                            .object(objectKey)
                            .expiry(expirationMinutes, TimeUnit.MINUTES)
                            .build()
            );

        } catch (Exception e) {
            log.error("Erreur lors de la génération de l'URL présignée: {}", e.getMessage(), e);
            throw new DocumentUploadException("Erreur de génération d'URL", e);
        }
    }

    @Override
    public void deleteFile(String bucketName, String objectKey) {
        try {
            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectKey)
                            .build()
            );

            log.debug("Fichier supprimé avec succès: {}/{}", bucketName, objectKey);

        } catch (Exception e) {
            log.error("Erreur lors de la suppression dans MinIO: {}", e.getMessage(), e);
            throw new DocumentUploadException("Erreur de suppression depuis le stockage", e);
        }
    }

    @Override
    public boolean fileExists(String bucketName, String objectKey) {
        try {
            minioClient.statObject(
                    StatObjectArgs.builder()
                            .bucket(bucketName)
                            .object(objectKey)
                            .build()
            );
            return true;

        } catch (Exception e) {
            return false;
        }
    }
}