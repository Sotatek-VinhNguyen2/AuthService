package com.thanhvinh.AuthService.dtos;

import lombok.Data;
import lombok.NonNull;

@Data
public class UserDTO {
    @NonNull
    private String gmail;
    @NonNull
    private String password;
}
