package com.lims.laboratory.dto.request;

import lombok.Data;

@Data
public class ExamenSearchDTO {
    private String nomExamen;
    private Boolean examenActif;
    private Boolean examenRealiseInternement;
}