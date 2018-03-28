package cn.com.sina.alan.oauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * Created by wanghongfei(hongfei7@staff.sina.com.cn) on 9/12/16.
 */
@Configuration
public class AlanOAuthWebConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// super.configure(http);
		// http.formLogin().permitAll().and().authorizeRequests().antMatchers("/health",
		// "/css/**")
		//
		// .anonymous().and().authorizeRequests().anyRequest().authenticated();
		http.formLogin().loginPage("/login").defaultSuccessUrl("/").usernameParameter("username")
				.passwordParameter("password").permitAll().and().requestMatchers()
				.antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access", "/user").and().csrf().disable()
				// .httpBasic()
				// 除以上路径都需要验证
				.authorizeRequests().anyRequest().authenticated();

	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/favor.ico");
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
		auth.parentAuthenticationManager(authenticationManager).inMemoryAuthentication().withUser("john")
				.password("123").roles("USER");
	}
}
