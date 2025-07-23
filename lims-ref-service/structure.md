src/main/java/com/lims/referential/
├── ReferentialServiceApplication.java
├── config/
│   ├── DatabaseConfig.java
│   ├── RedisConfig.java
│   ├── CacheConfig.java
│   └── OpenAPIConfig.java
├── controller/
│   ├── AnalyseController.java
│   ├── MedecinController.java
│   ├── LaboratoireController.java
│   ├── MedicamentController.java
│   ├── MutuelleController.java
│   ├── GeographiqueController.java
│   ├── PatientSpecificityController.java
│   ├── ValidationController.java
│   └── CacheController.java
├── service/
│   ├── AnalyseService.java
│   ├── MedecinService.java
│   ├── LaboratoireService.java
│   ├── MedicamentService.java
│   ├── MutuelleService.java
│   ├── GeographiqueService.java
│   ├── PatientSpecificityService.java
│   ├── ValidationService.java
│   └── CacheService.java
├── repository/
│   ├── AnalyseRepository.java
│   ├── MedecinRepository.java
│   ├── LaboratoireRepository.java
│   ├── MedicamentRepository.java
│   ├── MutuelleRepository.java
│   ├── GeographiqueRepository.java
│   └── PatientSpecificityRepository.java
├── entity/
│   ├── BaseEntity.java
│   ├── Analyse.java
│   ├── Medecin.java
│   ├── Laboratoire.java
│   ├── Medicament.java
│   ├── Mutuelle.java
│   ├── CodePostal.java
│   ├── PatientSpecificity.java
│   └── SpecificityCategory.java
├── dto/
│   ├── request/
│   │   ├── AnalyseRequestDTO.java
│   │   ├── MedecinRequestDTO.java
│   │   ├── LaboratoireRequestDTO.java
│   │   ├── MedicamentRequestDTO.java
│   │   ├── MutuelleRequestDTO.java
│   │   └── PatientSpecificityRequestDTO.java
│   ├── response/
│   │   ├── AnalyseResponseDTO.java
│   │   ├── MedecinResponseDTO.java
│   │   ├── LaboratoireResponseDTO.java
│   │   ├── MedicamentResponseDTO.java
│   │   ├── MutuelleResponseDTO.java
│   │   └── PatientSpecificityResponseDTO.java
│   └── common/
│       ├── PagedResponseDTO.java
│       ├── ErrorResponseDTO.java
│       └── ApiResponseDTO.java
├── enums/
│   ├── analyses/
│   │   ├── CategorieAnalyse.java
│   │   ├── NiveauUrgence.java
│   │   ├── TypeTube.java
│   │   └── CouleurTube.java
│   ├── medecins/
│   │   ├── Civilite.java
│   │   ├── SpecialiteMedicale.java
│   │   └── SecteurConventionnement.java
│   ├── laboratoires/
│   │   └── TypeLaboratoire.java
│   ├── medicaments/
│   │   └── ClasseTherapeutique.java
│   └── common/
│       ├── UniteTemps.java
│       └── TypeOrganisme.java
├── mapper/
│   ├── AnalyseMapper.java
│   ├── MedecinMapper.java
│   ├── LaboratoireMapper.java
│   ├── MedicamentMapper.java
│   ├── MutuelleMapper.java
│   └── PatientSpecificityMapper.java
├── exception/
│   ├── ResourceNotFoundException.java
│   ├── ValidationException.java
│   ├── DuplicateResourceException.java
│   └── GlobalExceptionHandler.java
└── util/
├── CacheConstants.java
├── ValidationUtils.java
├── GeographiqueUtils.java
└── CsvExportUtils.java