package com.cos.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

/*
 * 시큐리티가 가진 필터 중 BasicAuthenticationFilter라는 것이 있음.
 * 권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어있음.
 * 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않음.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
//		super.doFilterInternal(request, response, chain); // 응답 두 번 하므로 지워야됨
		System.out.println("112. 인증이나 권한이 필요한 주소가 요청됨");
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("113. " + jwtHeader);

		// header가 정상인지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰 검증해서 정상 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", ""); // 반드시 한칸 띄어야 함
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();
		// HMAC512로 암호화해서 빌드한 다음, jwt토큰을 서명, claim중 username을 들고 와서 스트링으로 캐스팅
		
		if(username != null) { // 서명이 제대로 됐으면
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			// jwt토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities()); // 강제로 Authentication 만드는 방법
			System.out.println("114. " + authentication.getPrincipal());
			SecurityContextHolder.getContext().setAuthentication(authentication); // 시큐리티 세션에 접근해서 Authentication객체를 저장			
		}
		chain.doFilter(request, response); // 뒤에 프로세스 진행하도록 설정
	}
}