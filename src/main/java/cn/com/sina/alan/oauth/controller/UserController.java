package cn.com.sina.alan.oauth.controller;

import java.security.Principal;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class UserController {

	@RequestMapping("/user")
	@ResponseBody
	public Principal user(Principal user) {
		return user;
	}

	// @RequestMapping(value = "/login", method = RequestMethod.GET)
	// public String login() {
	// System.out.println(111);
	// return "login";
	// }
	//
	// @RequestMapping("/oauth/confirm_access")
	// public String confirm_access() {
	// System.out.println(222);
	// return "authorize";
	// }

}
