package com.jmna.auth.repository;


import com.jmna.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    // TODO(#8): 5-1. 저장 시와 같은 규칙으로 정규화한 이메일로 검증된 회원을 찾는 조회를 추가한다.
    // TODO(#8): 5-2. 아래 공급자 조합 조회를 SocialAccount 저장소로 옮기고 연결된 User를 얻도록 한다.
    Optional<User> findByRegistrationIdAndProviderId(String registrationId, String providerId);
}
