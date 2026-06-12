package cn.iocoder.springboot.lab01.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

/**
 * Spring Security 配置类
 * 
 * @Configuration 注解说明：
 * 1. 标识该类为 Spring 的配置类，Spring 容器在启动时会扫描并加载此类
 * 2. 允许在该类中使用 @Bean 注解定义 Bean（虽然本例中未直接使用 @Bean）
 * 3. 与 @EnableWebSecurity 或继承 WebSecurityConfigurerAdapter 配合使用时，
 *    确保 Spring Security 的配置能够被正确识别和应用
 * 4. 使得 configure() 方法中的安全规则（如 URL 权限、表单登录等）生效
 * 
 * @EnableGlobalMethodSecurity 注解说明：
 * 1. prePostEnabled = true: 启用 Spring Security 的 @PreAuthorize 和 @PostAuthorize 注解
 *    - @PreAuthorize: 在方法执行前进行权限校验，支持 SpEL 表达式（如 hasRole('ADMIN')）
 *    - @PostAuthorize: 在方法执行后进行权限校验，通常用于基于返回结果的权限控制
 * 
 * 2. 其他可选参数（本例未启用）：
 *    - securedEnabled = true: 启用 @Secured 注解（JSR-250 标准之前的 Spring 专有注解）
 *    - jsr250Enabled = true: 启用 JSR-250 标准注解（如 @RolesAllowed, @PermitAll, @DenyAll）
 * 
 * 注意事项：
 * 1. 该注解必须配合 @Configuration 使用，且通常放在继承 WebSecurityConfigurerAdapter 的配置类上
 * 2. 启用后，可以在 Service 层或 Controller 层的方法上使用 @PreAuthorize 等注解进行细粒度权限控制
 * 3. 确保 Spring AOP 代理机制正常工作（默认使用 JDK 动态代理或 CGLIB），否则方法级安全控制可能不生效
 * 4. 如果使用的是 Spring Boot 2.x + Spring Security 5.x，此注解依然有效；但在 Spring Security 5.7+ 中，
 *    WebSecurityConfigurerAdapter 已被废弃，建议改用 SecurityFilterChain Bean 的方式配置，
 *    此时 @EnableGlobalMethodSecurity 可单独放在一个 @Configuration 类中
 * 5. prePostEnabled 默认为 false，必须显式设置为 true 才能使用 @PreAuthorize/@PostAuthorize
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 配置请求地址的权限
                .authorizeRequests()
                .antMatchers("/test/demo").permitAll() // 所有用户可访问
                .antMatchers("/test/admin").hasRole("ADMIN") // 需要 ADMIN 角色
                .antMatchers("/test/normal").access("hasAnyRole('NORMAL')") // 需要 NORMAL 角色。
                // 任何请求，访问的用户都需要经过认证
                .anyRequest().authenticated()
                .and()
                // 设置 Form 表单登陆
                .formLogin()
//                    .loginPage("/login") // 登陆 URL 地址
                .permitAll() // 所有用户可访问
                .and()
                // 配置退出相关
                .logout()
//                    .logoutUrl("/logout") // 退出 URL 地址
                .permitAll(); // 所有用户可访问
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.
                // 使用内存中的 InMemoryUserDetailsManager
                inMemoryAuthentication()
                // 不使用 PasswordEncoder 密码编码器
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                // 配置 admin 用户
                .withUser("admin").password("admin").roles("ADMIN")
                // 配置 normal 用户
                .and().withUser("normal").password("normal").roles("NORMAL");
    }

}
