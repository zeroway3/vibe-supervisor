package com.example.user;

import java.util.Random;
import org.springframework.stereotype.Component;

/** 로그 상관관계용 요청 ID 생성기 — 인증·세션에는 쓰지 않는다. */
@Component
public class RequestIdGenerator {
    public String nextRequestId() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }
}
