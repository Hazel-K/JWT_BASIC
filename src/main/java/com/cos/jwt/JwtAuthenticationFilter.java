package com.cos.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;


// 스프링 시큐리티에 이 필터가 있음
// /login 요청해서 username, password 전송하면 (post)
// 이 필터가 동작한다
// 하지만 이 필터는 formLogin에 합쳐져 있어서 disable된 상태에서는 이 필터 실행이 불가능함
// 그래서 이 필터를 다시 시큐리티 설정에 등록해야됨
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	private final AuthenticationManager authenticationManager;
	
	// /login요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		// username, password 받아서 정상인지 로그인 시도 해보기
		// authenticationManager를 사용해서 로그인 시도를 하면 PrincipalDetailsService가 호출되고, loadByUsername 함수가 실행됨
		// 이후 PrincipalDetails를 세션에 담고 (안담으면 권한 관리가 안됨) JWT 토큰을 만들어서 응답해주면 됨
		return super.attemptAuthentication(request, response);
	}
}