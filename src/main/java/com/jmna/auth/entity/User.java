package com.jmna.auth.entity;

import com.jmna.auth.dto.InfoUpdateRequest;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "member",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_member_registration_id_provider_id",
                        columnNames = {"registration_id", "provider_id"}
                )
        }
)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue
    @Column(name = "member_id")
    private Long id;

    // TODO(#8): 5-5. 자동 생성한 사용자명의 충돌을 막도록 사용자명 유일 제약을 DB 스키마에 반영한다.
    @Column(name = "member_name")
    private String username;

    // TODO(#8): 5-1. 서비스에서 확인한 이메일과 이메일 검증 시점을 저장한다.
    // 이메일은 정규화 규칙을 한 곳에서 적용하고 DB 유일 제약을 둔다. 기존 회원은 로그인 후 이메일을 확인한다.

    @Column
    private String password;

    // TODO(#8): 5-2. 두 필드를 SocialAccount 엔티티로 옮긴다. User는 List<SocialAccount>를 @OneToMany로 매핑한다.
    // SocialAccount는 user_id를 통해 User와 @ManyToOne으로 연결한다.
    // SocialAccount에 (registration_id, provider_id) 복합 유일 제약을 두고, 일반 회원은 빈 목록으로 시작한다.
    // MySQL에 새 테이블을 만든 뒤 두 ID가 있는 소셜 회원을 이관하고, 조회를 전환한 뒤 기존 컬럼과 제약을 정리한다.
    // providerId가 없는 예전 회원은 기존 계정 소유를 확인한 뒤 5-5에서 연결한다.
    @Column
    private String registrationId;

    @Column
    private String providerId;

    @Column
    @ElementCollection(fetch = FetchType.EAGER)
    private List<Roles> roles = new ArrayList<>();

    @Column
    private boolean isEnabled;

    @JoinColumn(name = "refresh_token_id")
    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private RefreshToken refreshToken;

    @Builder
    public User(String username, String password, String registrationId, String providerId, List<Roles> roles) {
        this.username = username;
        this.password = password;
        this.registrationId = registrationId;
        this.providerId = providerId;
        this.roles = new ArrayList<>(roles);
        this.isEnabled = true;
    }

    public void setToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void updatePassword(String newPassword) {
        this.password = newPassword;
    }

    public void updateDetails(InfoUpdateRequest dto) {
        this.username = dto.getNewName();
    }


}
