package com.yfsanchez.springboot.app.models.service;

import java.util.ArrayList;
import java.util.List;

import javax.swing.plaf.basic.BasicTreeUI.TreeHomeAction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.yfsanchez.springboot.app.models.dao.IUsuarioDao;
import com.yfsanchez.springboot.app.models.entity.Role;
import com.yfsanchez.springboot.app.models.entity.Usuario;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService{

	private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
	@Autowired
	IUsuarioDao usuarioDao;
	
	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Usuario usuario = usuarioDao.findByUsername(username);
		if (usuario == null) {
			logger.error("no existe el usuario");
			throw new UsernameNotFoundException("no existe el usuario ".concat(username).concat(" en el sistema"));
		}
		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		for (Role role : usuario.getRoles()) {
			authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
		}
		if (authorities.isEmpty()) {
			logger.error("sin roles el usario ".concat(username));
			throw new UsernameNotFoundException("no tiene roles el usuario ".concat(username).concat(" en el sistema"));
		}
		return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
	}

}
