package com.jmna.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class InfoUpdateRequest {
    private String username;
}
