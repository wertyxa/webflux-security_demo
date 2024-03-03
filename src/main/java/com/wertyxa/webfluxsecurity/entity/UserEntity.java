package com.wertyxa.webfluxsecurity.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder(toBuilder = true)
@Table("users")
public class UserEntity {
    @Id
    @Column("id")
    private Long id;

    @Column("username")
    private String username;
    @Column("password")
    private String password;
    @Column("role")
    private UserRole role;
    @Column("first_name")
    private String firstName;
    @Column("last_name")
    private String lastName;
    @Column("enabled")
    private Boolean enabled;
    @Column("created_at")
    private LocalDateTime createdAt;
    @Column("updated_at")
    private LocalDateTime updatedAt;

    @ToString.Include(name = "password")
    private String maskPassword(){
        return "********";
    }
}
