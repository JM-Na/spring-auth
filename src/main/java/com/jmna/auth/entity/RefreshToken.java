package com.jmna.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {

    @Id
    @GeneratedValue
    private Long id;

    @Column(columnDefinition = "TEXT")
    private String tokenValue; // RefreshToken 값

    @OneToOne(mappedBy = "refreshToken", fetch = FetchType.LAZY)
    private User user;

    public RefreshToken(String tokenValue, User user) {
        this.tokenValue = tokenValue;
        this.user = user;
    }

}
