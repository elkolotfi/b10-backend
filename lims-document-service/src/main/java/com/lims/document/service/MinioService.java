package com.lims.document.service;

import java.io.InputStream;

public interface MinioService {

    void uploadFile(String bucketName, String objectKey, InputStream inputStream,
                    long contentLength, String contentType);

    byte[] downloadFile(String bucketName, String objectKey);

    String generatePresignedUrl(String bucketName, String objectKey, int expirationMinutes);

    void deleteFile(String bucketName, String objectKey);

    boolean fileExists(String bucketName, String objectKey);
}