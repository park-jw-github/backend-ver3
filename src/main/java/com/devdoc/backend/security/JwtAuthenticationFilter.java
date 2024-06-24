package com.devdoc.backend.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

// JwtAuthenticationFilter: JWT 토큰을 기반으로 인증 필터를 구현

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private TokenProvider tokenProvider; // 토큰 제공자

    // 필터 실행
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = parseBearerToken(request); // 토큰 파싱
            log.info("Filter is running...");

            if (token != null && !token.equalsIgnoreCase("null")) {
                String userId = tokenProvider.validateAndGetUserId(token); // 토큰 검증 및 사용자 ID 추출
                log.info("Authenticated user ID : " + userId );

                // 인증 객체 생성
                AbstractAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        AuthorityUtils.NO_AUTHORITIES
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // 인증 객체에 요청 정보 설정
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext(); // 빈 보안 컨텍스트 생성
                securityContext.setAuthentication(authentication); // 보안 컨텍스트에 인증 객체 설정
                SecurityContextHolder.setContext(securityContext); // 보안 컨텍스트 설정
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex); // 예외 처리
        }

        filterChain.doFilter(request, response); // 다음 필터로 요청 전달
    }

    // 요청 헤더에서 Bearer 토큰 파싱
    private String parseBearerToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization"); // Authorization 헤더에서 토큰 추출

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Bearer 접두사 제거 후 토큰 반환
        }
        return null; // 토큰이 없으면 null 반환
    }
}