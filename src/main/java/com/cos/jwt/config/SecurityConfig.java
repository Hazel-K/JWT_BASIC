package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.JwtAuthenticationFilter;
import com.cos.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final UserRepository userRepository;
	private final CorsFilter corsFilter;
	
	// IoC에서 패스워드 인코드를 찾지 못하므로 Bean으로 등록시켜줌
	// 등록시켜주면 Security에서 알아서 이것을 찾아 비밀번호를 Encoding함
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class); // 시큐리티에 필터 거는 법
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다는 말
		.and()
		.addFilter(corsFilter) // restController에 @CrossOrigin 거는 것과 차이점: 전자는 인증이 필요없는 요청만 허용된다.
		// corsFilter 설정으로 인해 인증이 필요하지 않은 모든 페이지는 Security가 있음에도 불구하고 접속이 가능함 
		.formLogin().disable() // 기본 로그인 폼 안쓴다
		.httpBasic().disable() // 기본 http 형식도 안쓴다
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) // 이 필터 전달시 꼭 전달해야하는 파라미터가 있음(AuthenticationManager), 이 파라미터는 이 클래스가 extends한 클래스에 미리 담겨있어 쉽게 사용 가능
		.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
	}
}