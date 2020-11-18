package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
		System.out.println("필터3");
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse res = (HttpServletResponse)response;
		
		req.setCharacterEncoding("UTF-8"); // 이거 해봐야 어짜피 Auth에 한글은 안들어감
		// 토큰: cos 만들어야됨. id, pw 정상적으로 들어와서 로그인 완료되면 토큰 생성
		// 요청할 때마다 header에 Authorization value로 토큰을 갖고옴
		// 그때 토큰이 넘어오면 이 토큰이 내가 만든 것이 맞는지만 검증하면 됨(RSA, HS256)
		// 토큰 이름이 만약 cos라면
		if(req.getMethod().equals("POST")) {
			System.out.println("포스트 요청됨");
			String headerAuth = req.getHeader("Authorization");
			System.out.println("111. " + headerAuth);
			
			if(headerAuth.equals("cos")) {
				chain.doFilter(req, res);
			} else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
			}
		}
	}
}
