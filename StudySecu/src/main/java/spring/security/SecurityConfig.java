package spring.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import spring.security.handler.CustomAccessDeniedHandler;
import spring.security.handler.CustomAuthenticationEntryPoint;

import java.io.IOException;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    UserDetailsService userDetailsService;

    @Autowired
    CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    @Autowired
    CustomAccessDeniedHandler customAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorizeRequests) ->
                    authorizeRequests
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")
                        .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                        .anyRequest().authenticated()
                )

                .formLogin(formLogin ->
                    formLogin
                        // .loginPage("/loginPage")  // 우리는 이 페이지에서 로그인을 시킬것이다!!
                        .defaultSuccessUrl("/")  // 성공했다면 이동하는 페이지
                        .failureUrl("/login") // 로그인을 실패한다면 이동하는 로그인 페이지
                        .usernameParameter("myMan") // html 에 보면 아이디 쪽의 name 이 바뀐다
                        .passwordParameter("myWoman")  // html 에 보면 비밀번호 쪽의 name 이 바뀐다
                        .loginProcessingUrl("/login_proc")  // 로그인 Form Action Url
                        .successHandler(new AuthenticationSuccessHandler() {   // 로그인이 성공한 후에 작동하는 핸들러
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                                Authentication authentication) throws IOException, ServletException {
                                System.out.println("authentication" + authentication.getName());

                                // 원래 하려고 했던 내용을 저장하고 성공하면 저장된 자료 다시 보내줌
                                RequestCache requestCache = new HttpSessionRequestCache();
                                SavedRequest savedRequest = requestCache.getRequest(request, response);
                                String redirectUrl = savedRequest.getRedirectUrl();
                                response.sendRedirect(redirectUrl);
                                }
                            })  // 해당 파라미터로는 인증이 성공한 객체 Authentication 이 있다.
                            .failureHandler(new AuthenticationFailureHandler() {
                                @Override
                                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                                    AuthenticationException exception) throws IOException, ServletException {
                                   System.out.println("exception" + exception.getMessage());
                                   response.sendRedirect("/login");
                                }
                            })  // 해당 파라미터로는 인증이 실패한 후 나오는 예외처피 exception 이 있다.
                            .permitAll() // 로그인 페이지는 딱히 인증을 받지 않아도 이용할 수 있어야 한다.
                )

                .logout(logout ->
                    logout
                        .logoutUrl("/logout")   // 로그아웃을 하는 URL
                        .logoutSuccessUrl("/login") // 로그아웃이 성공하면 가는 URL
                        .addLogoutHandler(new LogoutHandler() {  // 로그 아웃을 하면 세션을 무효화한다.
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();
                            }
                        })
                        .logoutSuccessHandler(new LogoutSuccessHandler() {  // 로그 아웃이 성공하면 가는 url 을 설정해주는 곳 URL 과는 다르게 로그아웃을 하면 나타나는 다양한 로직을 작성할수있다.
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/login");
                            }
                        })
                        .deleteCookies("remember-me") // 서버에서 만든 쿠키를 삭제하는것이다.
                )

                .rememberMe(rememberMe ->
                    rememberMe
                        .rememberMeParameter("remember")  // 설정칸에 나오는 말
                        .tokenValiditySeconds(3600) // 토큰의 유효시간
                        .userDetailsService(userDetailsService)  // 인증을 사용할 객체를 만들고 Autowired 까지 완료
                )

                .sessionManagement(sessionManagement ->
                    sessionManagement
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                            .sessionFixation().changeSessionId()
                            .invalidSessionUrl("/")
                            .maximumSessions(1)
                            .expiredUrl("/")
                            .maxSessionsPreventsLogin(true)  // true : 이전 동일 사용자의 세션 유지 false : 이전 사용자의 세션 삭제
                )

                .exceptionHandling(exceptionHandling ->
                    exceptionHandling
                        .authenticationEntryPoint(customAuthenticationEntryPoint) // 인증예외 ( 다시 로그인을 요청 )
                        .accessDeniedHandler(customAccessDeniedHandler) // 인가 예외 ( 해당 페이지는 사용 할 수 없다는 경고 )
                )

                .csrf(AbstractHttpConfigurer::disable);

        // 이건 따로 설정하는것이다 http 안에 설정하는 것이 아니다
        // 해당 설정을 하는 이유는 부모 쓰레드와 자식 쓰레드는 서로의 정보를 공유하지 않는데 이를 공유하기 위해서 하는것이다.
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        return http.build();
    }

    @Bean
    public SecurityFilterChain secondFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/firstFilter")
                .authorizeHttpRequests((authz) ->
                        authz.requestMatchers("/king/**").authenticated()
                )
                .httpBasic(Customizer.withDefaults())
        ;

        return http.build();
    }

    @Bean
    @Order(0)
    public SecurityFilterChain thiredFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/secondFilter")
                .authorizeHttpRequests(authz ->
                        authz
                                .requestMatchers("/nomal/**").authenticated()
                )
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }

    @Bean
    public static UserDetailsService users() {

        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER")
                .build();

        return new InMemoryUserDetailsManager( user, sys, admin );
    }
}
