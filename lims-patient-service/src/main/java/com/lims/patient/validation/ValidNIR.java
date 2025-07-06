package com.lims.patient.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

/**
 * Annotation pour valider le format du NIR (Numéro de Sécurité Sociale français)
 */
@Documented
@Constraint(validatedBy = NIRValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidNIR {
    String message() default "Le numéro de sécurité sociale n'est pas valide";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
