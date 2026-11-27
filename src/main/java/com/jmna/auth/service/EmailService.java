package com.jmna.auth.service;

import com.jmna.auth.dto.SendEmailRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    // TODO(#8): 5-1.1. 문자열 키와 검증 데이터를 넘길 수 있도록 RedisConfig의 빈 타입에 맞춘다.
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();
    private final JavaMailSender mailSender = new JavaMailSenderImpl();

    @Value("${email.key}")
    private String emailKey;
    @Value("${email.algorithm}")
    private String emailAlgorithm;
    @Value("${smtp.from}")
    private String smtpFrom;
    @Value("${smtp.host}")
    private String smtpHost;
    @Value("${smtp.port}")
    private String smtpPort;
    @Value("${smtp.username}")
    private String smtpUsername;
    @Value("${smtp.from}")
    private String smtpPassword;

    public String sendEmail(SendEmailRequest dto) throws NoSuchAlgorithmException, InvalidKeyException {
        // TODO(#8): 5-1.1. 이메일은 도메인만 소문자로 바꿔 저장과 조회에서 같은 주소를 비교한다.
        String email = dto.getEmail();

        String challengeId = UUID.randomUUID().toString();
        String code = String.format(Locale.ROOT, "%06d", secureRandom.nextInt(1_000_000));

        // 이 HMAC 계산은 발송과 확인에서 공유할 수 있게 byte[]를 반환하는 메서드로 빼 본다.
        SecretKeySpec secretKey = new SecretKeySpec(emailKey.getBytes(), emailAlgorithm);

        Mac mac = Mac.getInstance(emailAlgorithm);
        mac.init(secretKey);

        byte[] input = (challengeId + ":" + code).getBytes(StandardCharsets.UTF_8);
        byte[] hmac = mac.doFinal(input);
        String codeVerifier = Base64.getEncoder().encodeToString(hmac);

        // TODO(#8): 5-1.1. signup:email:code:<challengeId>에 이메일, codeVerifier, remainingAttempts를 담는다.
        // HashMap<String, Object>를 값으로 넘기고, Redis에 저장할 때 TTL을 지정한다(예시 5분).
        String redisKey = "signup:email:code:" + challengeId;
        Map<String, Object> map = new HashMap<>();
        map.put("email", email);
        map.put("codeVerifier", codeVerifier);
        map.put("remainingAttempts", 5);
        redisTemplate.opsForValue().set(redisKey, map, Duration.ofMinutes(5));

        // 원본 코드는 메일로 보내고 발송 응답에는 challengeId를 담는다.
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(smtpFrom);
        message.setTo(email);
        message.setSubject("회원가입 이메일 인증");
        message.setText("인증 코드는" + code + "입니다. 5분안에 입력해주세요");


        return challengeId;
    }

    // TODO(#8): 5-1.2. 여기에 이메일 코드 확인 메서드를 추가한다.
    // 1. 요청의 challengeId로 발송 때와 같은 Redis 키를 만들어 읽는다. 값이 없거나 남은 시도가 없으면 중단한다.
    // 2. 저장값이 Map인지 확인하고 codeVerifier를 String으로 꺼내 Base64 디코딩한다.
    // 3. 요청의 verifyCode를 발송 때와 같은 challengeId + ":" + code 형식으로 넣어 HMAC을 다시 계산한다.
    // 4. 저장된 검증값을 디코딩한 바이트와 새 HMAC 바이트를 MessageDigest.isEqual(...)로 비교한다.
}
