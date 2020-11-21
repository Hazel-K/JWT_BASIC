package com.cos.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

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
		try {
//			System.out.println(request.getInputStream()); // 이 안에 username, password 다 있음
			// 이 정보를 불러오는 가장 원시적인 방법
//			BufferedReader br = request.getReader();
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//			}
			// JSON 사용시 좋은 방법
			ObjectMapper om = new ObjectMapper(); // 이친구가 JSON객체를 parsing해줌
			User user = om.readValue(request.getInputStream(), User.class); // 유저 Obj에 JSON 객체 담아줌
			System.out.println("11. " + user);
			
			// 이제 토큰 만들어서 로그인 시도. FormLogin을 사용한다면 자동으로 해주는 부분임
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			Authentication authentication = authenticationManager.authenticate(authenticationToken); // 이것이 실행되면 PrincipalDetailsService의 loadUserByUsername()이 실행됨
			// 그리고 authentication에는 내 로그인한 정보가 담기게 됨
			// 인증이 정상적으로 완료되면 authentication 객체는 session에 저장됨 (로그인이 정상적으로 됐다는 뜻)
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal(); // authentication 로그인 정보 받기
			System.out.println("13. " + principalDetails.getUsername());
			return authentication; // 세션에 저장
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("=======================================");
		// authenticationManager를 사용해서 로그인 시도를 하면 PrincipalDetailsService가 호출되고, loadByUsername 함수가 실행됨
		// 이후 PrincipalDetails를 세션에 담고 (안담으면 권한 관리가 안됨) JWT 토큰을 만들어서 응답해주면 됨
//		return super.attemptAuthentication(request, response); // 구현중에 오류 안내기 위해 부모의 결과 호출
		return null;
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		// RSA 방식은 아니고 Hash 암호방식
		String jwtToken = JWT.create() // jwt 토큰 생성
				.withSubject("cos토큰") // 토큰 이름
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) // 현재 시간 + 내가 정한 만료 시간
				.withClaim("id", principalDetails.getUser().getId()) // 비공개 클레임
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET)); // HMAC은 서버만 알고 있는 값이 있어야됨
		
		System.out.println("successfulAuthentication 실행됨: 인증 완료됐다는뜻");
		response.addHeader("Authorization", "Bearer " + jwtToken); // Bearer다음 무조건 한칸 띄어야 됨
		
		// <일반적인 방식>
		// 유저네임, 패스워드 로그인 정상
		// 서버쪽 세션ID 생성
		// 클라이언트 쿠키 세션 ID를 응답
		// session.getAttribute로 인식
		// 요청할 때마다 쿠키값 세션 ID를 항상 들고 요청하기 때문에 서버는 세션 ID가 유효한지 판단해서 유효하면 인증이 필요한 페이지로 접근하게 하면 됨
		
		// <이 프로젝트에서 방식>
		// 유저네임, 패스워드 로그인 정상
		// JWT 토큰생성
		// 클라이언트 쪽으로 JWT 발급
		// 요청할 때마다 JWT 토큰으로 요청
		// 서버는 토큰이 유효한지를 판단 (필터 만들어야 함)
	}
}