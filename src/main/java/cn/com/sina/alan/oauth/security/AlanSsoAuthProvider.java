package cn.com.sina.alan.oauth.security;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Created by wanghongfei(hongfei7@staff.sina.com.cn) on 9/11/16.
 */
@Component
public class AlanSsoAuthProvider implements AuthenticationProvider {
	// @Bean
	// DaoAuthenticationProvider daoAuthenticationProvider() {
	// DaoAuthenticationProvider daoAuthenticationProvider = new
	// DaoAuthenticationProvider();
	// daoAuthenticationProvider.setPasswordEncoder(new
	// BCryptPasswordEncoder());
	// daoAuthenticationProvider.setUserDetailsService(userServiceDetails);
	// return daoAuthenticationProvider;
	// }

	private static final Logger log = LoggerFactory.getLogger(AlanSsoAuthProvider.class);
	private final String adminName = "root";
	private final String adminPassword = "root";

	// 根用户拥有全部的权限
	private final List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("CAN_SEARCH"),
			new SimpleGrantedAuthority("CAN_SEARCH"), new SimpleGrantedAuthority("CAN_EXPORT"),
			new SimpleGrantedAuthority("CAN_IMPORT"), new SimpleGrantedAuthority("CAN_BORROW"),
			new SimpleGrantedAuthority("CAN_RETURN"), new SimpleGrantedAuthority("CAN_REPAIR"),
			new SimpleGrantedAuthority("CAN_DISCARD"), new SimpleGrantedAuthority("CAN_EMPOWERMENT"),
			new SimpleGrantedAuthority("CAN_BREED"));

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		System.out.println(111111);
		if (isMatch(authentication)) {
			User user = new User(authentication.getName(), authentication.getCredentials().toString(), authorities);
			return new UsernamePasswordAuthenticationToken(user, authentication.getCredentials(), authorities);
		}
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

	private boolean isMatch(Authentication authentication) {
		if (authentication.getName().equals(adminName) && authentication.getCredentials().equals(adminPassword))
			return true;
		else
			return false;
	}

	// @Override
	// public Authentication authenticate(Authentication authentication) throws
	// AuthenticationException {
	// log.debug("自定义provider调用");
	// System.out.println("自定义provider调用");
	// // 返回一个Token对象表示登陆成功
	// return new
	// UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
	// authentication.getCredentials(),
	// Collections.<GrantedAuthority>emptyList());
	// }
	//
	// @Override
	// public boolean supports(Class<?> aClass) {
	// return true;
	// }
}
