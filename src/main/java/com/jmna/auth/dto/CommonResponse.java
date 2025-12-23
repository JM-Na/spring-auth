package com.jmna.auth.dto;

import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
public class CommonResponse {
    private String message;
}
