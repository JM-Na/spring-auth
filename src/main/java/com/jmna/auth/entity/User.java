package com.jmna.auth.entity;

import com.jmna.auth.dto.InfoUpdateRequest;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity(name = "member")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue
    @Column(name = "memberId")
    private Long id;

    @Column(name = "memberName")
    private String username;

    @Column
    private String password;

    @Column
    private String provider;

    @Column
    private String providerId;

    @Column
    @ElementCollection(fetch = FetchType.EAGER)
    private List<Roles> roles;

    @Column
    private boolean isEnabled;

    @JoinColumn(name = "refresh_token_id")
    @OneToOne(fetch = FetchType.LAZY)
    private RefreshToken refreshToken;

    @Builder
    public User(String username, String password, String provider,List<Roles> roles) {
        this.username = username;
        this.password = password;
        this.provider = provider;
        this.roles = roles;
        this.isEnabled = true;
    }

    public void setToken (RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void updatePassword(String newPassword) {
        this.password = newPassword;
    }

    public void updateDetails(InfoUpdateRequest dto) {
        this.username = dto.getUsername();
    }


}
