package com.yfsanchez.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.yfsanchez.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.yfsanchez.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.yfsanchez.springboot.app.auth.service.JWTService;
import com.yfsanchez.springboot.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecuryConfig extends WebSecurityConfigurerAdapter{
//	@Autowired
//	private LoginSuccessHandler successHandler;
	
//	@Autowired
//	private DataSource datasource;
	
	@Autowired
	private JpaUserDetailsService jpaUserDetailsService;
	
	@Autowired
	private JWTService jwtService;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/","/css/**","/js/**","/images/**","/listar**","/locale").permitAll()
//		.antMatchers("/ver/**").hasAnyRole("USER")
//		.antMatchers("/uploads/**").hasAnyRole("USER")
//		.antMatchers("/form/**").hasAnyRole("ADMIN")
//		.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
//		.antMatchers("/factura/**").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
//		.and()
//			.formLogin()
//				.successHandler(successHandler)
//				.loginPage("/login")
//			.permitAll()
//		.and()
//			.logout().permitAll()
//		.and()
//			.exceptionHandling().accessDeniedPage("/error_403")
		
			.and()
			.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
			.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception{
		PasswordEncoder encoder = passwordEncoder();
//		UserBuilder users = User.builder().passwordEncoder(password -> {return encoder.encode(password);});

//		UserBuilder users = User.builder().passwordEncoder(password -> encoder.encode(password));

//		UserBuilder users = User.builder().passwordEncoder(encoder :: encode);
//		builder.inMemoryAuthentication()
//		.withUser(users.username("admin").password("1234").roles("ADMIN","USER"))
//		.withUser(users.username("andres").password("1234").roles("USER"));
		
//		builder.jdbcAuthentication()
//		.dataSource(datasource)
//		.passwordEncoder(encoder)
//		.usersByUsernameQuery("select username,password,enabled from users where username=?")
//		.authoritiesByUsernameQuery("select u.username,a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");
		
		builder.userDetailsService(jpaUserDetailsService)
		.passwordEncoder(encoder);
	}
}
