package project.practice.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("CustomAuthenticationSuccessHandler.onAuthenticationSuccess");
        setDefaultTargetUrl("/");

        // 인증이 성공하기 전에 담고있는 사용자의 요청 정보를 가져오기
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            // 만약 targetUrl 이 이전에 가고자 했던 URL 이면 해당 코드로 이동 시킨다.
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            // savedRequest 가 null 이면 기본 페이지로 이동한다.
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
