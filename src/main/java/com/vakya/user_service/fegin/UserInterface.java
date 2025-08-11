package com.vakya.user_service.fegin;

import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "POST-SERVICE")
public interface UserInterface {
}
