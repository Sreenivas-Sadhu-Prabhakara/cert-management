package com.certmgmt.web.dto;

public record SubjectDto(
        String commonName,
        String organization,
        String organizationalUnit,
        String country,
        String state,
        String locality) {}
