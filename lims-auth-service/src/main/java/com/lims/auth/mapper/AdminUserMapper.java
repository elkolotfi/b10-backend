package com.lims.auth.mapper;

import com.lims.auth.config.MapStructConfig;
import com.lims.auth.dto.response.AdminUserResponse;
import com.lims.auth.entity.AdminUser;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

@Mapper(config = MapStructConfig.class)
public interface AdminUserMapper {

    @Mapping(target = "fullName", source = ".", qualifiedByName = "mapFullName")
    @Mapping(target = "realm", constant = "lims-admin")
    @Mapping(target = "userType", constant = "ADMIN")
    @Mapping(target = "role", source = "role", qualifiedByName = "mapRole")
    @Mapping(target = "status", source = "status", qualifiedByName = "mapStatus")
    @Mapping(target = "temporarilyLocked", source = ".", qualifiedByName = "mapTemporarilyLocked")
    AdminUserResponse toResponse(AdminUser adminUser);

    @Named("mapFullName")
    default String mapFullName(AdminUser adminUser) {
        if (adminUser.getFirstName() == null && adminUser.getLastName() == null) {
            return null;
        }
        return (adminUser.getFirstName() != null ? adminUser.getFirstName() : "") +
                " " +
                (adminUser.getLastName() != null ? adminUser.getLastName() : "");
    }

    @Named("mapRole")
    default String mapRole(AdminUser.AdminRole role) {
        return role != null ? role.name() : null;
    }

    @Named("mapStatus")
    default String mapStatus(AdminUser.AdminStatus status) {
        return status != null ? status.name() : null;
    }

    @Named("mapTemporarilyLocked")
    default boolean mapTemporarilyLocked(AdminUser adminUser) {
        return adminUser.isTemporarilyLocked();
    }
}