package com.yfsanchez.springboot.app.controllers;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class LoginController {
	
	@GetMapping("/login")
	public String login(@RequestParam(value = "error", required = false) String error,
			@RequestParam(value = "logout", required = false) String logout,
			Model model, Principal principal, RedirectAttributes msgFlash) {
		if (principal != null) {
			msgFlash.addFlashAttribute("info", "Ya estaba logeado.");
			return "redirect:/";
		}
		if (error != null) {
			System.out.println("error");
			model.addAttribute("error", "Error en el login, usuario o password incorrecto.");
			
		}
		if (logout != null) {
			System.out.println("logout");
			model.addAttribute("success", "Session cerrada con exito.");
			
		}
		return "login";
	}

}
