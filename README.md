# spring-auth

Spring Security에서 JSON 로그인, OAuth2 로그인, JWT 발급과 갱신을 연결한 학습용 인증 서버입니다. 로그인 이름을 바꾼 뒤에도 같은 계정을 식별할 수 있도록 JWT의 `sub`에는 내부 회원 ID를 넣습니다.

## 인증 흐름

1. `POST /auth/login`이 JSON 본문의 `username`, `password`를 인증합니다. OAuth2 콜백은 별도 필터 체인에서 처리합니다. 두 경로 모두 성공 시 회원 ID로 액세스 토큰과 리프레시 토큰을 발급합니다.
2. 보호 API를 호출할 때는 액세스 토큰을 `Authorization: Bearer <access-token>` 헤더에 담습니다. [JWT 필터](src/main/java/com/jmna/auth/filter/CustomJwtAuthenticationFilter.java)가 토큰을 확인하고 인증된 사용자를 설정합니다.
3. `GET /auth/refresh`에는 리프레시 토큰을 같은 헤더로 보냅니다. [토큰 서비스](src/main/java/com/jmna/auth/service/TokenService.java)가 회원 ID로 계정을 찾고, JPA에 저장한 리프레시 값과 일치할 때 새 액세스 토큰을 반환합니다. 로그아웃 시 저장된 리프레시 토큰을 삭제합니다.

## 계정 변경

`PATCH /auth/user`의 `username`에는 현재 사용자명을, `newName`에는 바꿀 이름을 전달합니다. [회원 서비스](src/main/java/com/jmna/auth/service/UserService.java)에서 인증 사용자와 요청 대상의 일치를 확인하고 새 이름의 공백과 중복 여부를 검사합니다. 비밀번호 변경과 탈퇴 경로에서는 현재 비밀번호도 확인합니다. 전체 경로와 요청 DTO는 [인증 컨트롤러](src/main/java/com/jmna/auth/controller/AuthController.java)에서 볼 수 있습니다.

## 로컬 실행

JDK 21과 Gradle Wrapper를 사용합니다. 개발용 Spring 설정에 다음 값을 준비합니다.

| 설정 | 용도 |
| --- | --- |
| `expire.access`, `expire.refresh` | 액세스 토큰의 만료 시간(분), 리프레시 토큰의 만료 기간(일) |
| `spring.data.redis.host`, `spring.data.redis.port` | Redis 연결 빈에 사용할 호스트와 포트 |
| `oauth.<provider>.client-id`, `oauth.<provider>.client-secret` | 시작 시 등록하는 kakao, naver, github, google 클라이언트 설정 |
| `spring.datasource.*` | 회원·리프레시 토큰을 보관할 JPA 데이터베이스 설정. 빌드에 H2와 MySQL 드라이버가 포함돼 있습니다. |

```sh
sh gradlew bootRun
```

Windows PowerShell에서는 `.\gradlew.bat bootRun`을 실행합니다. OAuth2 로그인에 사용할 콜백 주소는 각 제공자 콘솔과 [OAuth2 설정](src/main/java/com/jmna/auth/config/OAuth2SecurityConfig.java)에 맞춰 등록합니다.

## 테스트에서 확인할 수 있는 사례

[TokenServiceTest](src/test/java/com/jmna/auth/service/TokenServiceTest.java)는 로컬·OAuth2 로그인의 토큰에 담긴 회원 ID, 사용자명 변경 후의 식별, 알 수 없는 회원 ID와 이전 형식의 토큰을 다룹니다. [UserServiceTest](src/test/java/com/jmna/auth/service/UserServiceTest.java)에는 계정 변경 사례가 있습니다. 개발·테스트 설정을 준비한 뒤 `sh gradlew test`로 실행합니다.
