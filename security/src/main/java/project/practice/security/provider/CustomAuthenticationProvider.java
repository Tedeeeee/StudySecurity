package project.practice.security.provider;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import project.practice.security.service.AccountContext;
import project.practice.security.service.CustomUserDetailsService;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final BCryptPasswordEncoder passwordEncoder;

    // 인증을 위한 검증 구현
    // 여기서 파라미터인 authentication 은 manager 가 전달해준 인증되지 않은 authentication 객체이다.
    // 현재 패스워드만 검증했지만 추가적으로 더 검증해도 상관없음
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("CustomAuthenticationProvider.authenticate");

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) customUserDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        // 검증이 완료되면 UsernamePasswordAuthenticationToken 에 담아 Authentication 객체에 담는다.
        // accountContext 는 UserDetails 의 구현체와 마찬가지 이므로 해당 메소드를 사용해서 값을 설정해야한다.
        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(),
                null, accountContext.getAuthorities());
    }

    // 전달온 파라미터와 우리가 사용하고자 하는 토큰 클래스의 타입이 일치하는지 확인
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        // authentication.equals(UsernamePasswordAuthenticationToken.class) 이렇게 작성할수 있다.
    }
}
