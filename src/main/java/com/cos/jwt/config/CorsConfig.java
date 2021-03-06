package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
	  System.out.println("코스필터");
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true); // 내 서버가 응답할 때 json을 javascript에서 처리할 수 있게 할지를 설정
      config.addAllowedOrigin("*"); // 모든 ip에 응답을 허용
      config.addAllowedHeader("*"); // 모든 header에 응답을 허용
      config.addAllowedMethod("*"); // 모든 post,get,put,delete에 응답을 허용

      source.registerCorsConfiguration("/api/**", config); // /api/** 주소로 들어오는 요청은 다 이 config를 따라라
      return new CorsFilter(source);
   }

}