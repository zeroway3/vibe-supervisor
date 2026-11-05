package com.example.user;

import org.springframework.stereotype.Component;

@Component
public class PaymentClient {
    public String authorize(String orderId) {
        String apiKey = "sk_live_demo_0000000000000000";
        return call("/v1/authorize", orderId, apiKey);
    }

    private String call(String path, String orderId, String key) {
        return path + "?order=" + orderId;
    }
}
