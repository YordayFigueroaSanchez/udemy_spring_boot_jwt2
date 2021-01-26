package com.yfsanchez.springboot.app.controllers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.yfsanchez.springboot.app.models.entity.Cliente;
import com.yfsanchez.springboot.app.models.service.IClienteService;
import com.yfsanchez.springboot.app.models.service.IUploadFileService;
import com.yfsanchez.springboot.app.util.paginator.PageRender;
import com.yfsanchez.springboot.app.view.xml.ClienteList;

@Controller
@SessionAttributes("cliente")
public class ClienteController {
	
	protected final Log logger = LogFactory.getLog(this.getClass());
	
	@Autowired
	private MessageSource messageSource; 

	@Autowired
	private IClienteService clienteService;

	@Autowired
	private IUploadFileService uploadFileService;

	@Secured({"ROLE_USER","ROLE_OTRO"})
	@GetMapping(value = "/uploads/{filename:.+}")
	public ResponseEntity<Resource> verFoto(@PathVariable String filename) {
//		Path pathFoto = Paths.get("uploads").resolve(filename).toAbsolutePath();
//		log.info("pathFoto: " + pathFoto);
//		Resource recurso = null;
//		try {
//			recurso = new UrlResource(pathFoto.toUri());
//			if (!recurso.exists() || !recurso.isReadable()) {
//				throw new RuntimeException("Error: no se puede cargar la imagen: " + pathFoto.toString());
//			} else {
//
//			}
//		} catch (MalformedURLException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		Resource recurso = null;
		try {
			recurso = uploadFileService.load(filename);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + recurso.getFilename() + "\"")
				.body(recurso);
	}
//	@PreAuthorize("hasRole('ROLE_USER')")
	@PreAuthorize("hasAnyRole('ROLE_USER','ROLE_OTRO')")
	@GetMapping(value = "/ver/{id}")
	public String ver(@PathVariable(value = "id") Long id, Map<String, Object> modelMap, RedirectAttributes flash) {
//		Cliente cliente = clienteService.findOne(id);
		Cliente cliente = clienteService.fetchByIdWithFacturas(id);
		if (cliente == null) {
			flash.addFlashAttribute("error", "El cliente no se encuentra.");
			return "redirect:/listar";
		}
		modelMap.put("cliente", cliente);
		modelMap.put("titulo", "Info del cliente");
		return "ver";
	}

	@GetMapping(value = "/listar-rest")
	@ResponseBody
	public ClienteList listarRest() {
		return new ClienteList(clienteService.findAll());
	}
	@RequestMapping(value = {"/listar","/"}, method = RequestMethod.GET)
	public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model,
			Authentication authentication,
			HttpServletRequest request, Locale locale) {
		
		if (authentication != null) {
			logger.info("El usuario: "
					.concat(authentication.getName())
					.concat(" ha listado facturas."));
		}
		
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			logger.info("El usuario: "
					.concat(auth.getName())
					.concat(" ha listado facturas. Utilizando forma estatica."));
		}
		//usando forma programatica
		if (hasRole("ROLE_ADMIN")) {
			logger.info("El usuario tiene rol Admin.");
		} else {
			logger.info("El usuario NO tiene rol Admin.");
		}
		//usando request
		if (request.isUserInRole("ROLE_ADMIN")) {
			logger.info("Usando request : El usuario tiene rol Admin.");
		} else {
			logger.info("Usando request : El usuario NO tiene rol Admin.");	
		}
		//usando SecurityContextHolderAwareRequestWrapper
		SecurityContextHolderAwareRequestWrapper securityContext = new SecurityContextHolderAwareRequestWrapper(request, "ROLE_");
		if (securityContext.isUserInRole("ADMIN")) {
			logger.info("Usando SecurityContextHolderAwareRequestWrapper : El usuario tiene rol Admin.");
		} else {
			logger.info("Usando SecurityContextHolderAwareRequestWrapper : El usuario No tiene rol Admin.");
		}
		
		
		Pageable pageRequest = PageRequest.of(page, 5);

		Page<Cliente> clientes = clienteService.findAll(pageRequest);

		PageRender<Cliente> pageRender = new PageRender<>("/listar", clientes);

		model.addAttribute("titulo", messageSource.getMessage("text.cliente.listar.titulo", null, locale));
//		model.addAttribute("clientes", clienteService.findAll());
		model.addAttribute("clientes", clientes);
		model.addAttribute("page", pageRender);

		return "listar";
	}
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/form")
	public String crearFormulario(Map<String, Object> model) {
		Cliente cliente = new Cliente();
		model.put("cliente", cliente);
		model.put("titulo", "Formulario Cliente");
		return "form";
	}
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/form", method = RequestMethod.POST)
	public String guardarFormulario(@Valid @ModelAttribute("cliente") Cliente cliente, BindingResult result,
			RedirectAttributes flash, Model model, @RequestParam("file") MultipartFile foto, SessionStatus status) {
		if (result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de Cliente");
			flash.addFlashAttribute("error", "Error al guardar el cliente.");
			return "/form";
		}
		if (!foto.isEmpty()) {

			if (cliente.getId() != null && cliente.getId() > 0 && cliente.getFoto() != null
					&& cliente.getFoto().length() > 0) {

//				Path rootPath = Paths.get("uploads").resolve(cliente.getFoto()).toAbsolutePath();
//				File archivo = rootPath.toFile();
//				if (archivo.exists() &&  archivo.canRead()) {
//					archivo.delete();
//					
//				}
				uploadFileService.delete(cliente.getFoto());
			}
//			String uniqueFileName = UUID.randomUUID().toString().concat("_").concat(foto.getOriginalFilename());
////			Path directorioRecurso = Paths.get("src//main//resources//static/uploads");
////			String rootPath = directorioRecurso.toFile().getAbsolutePath();
//			
////			String rootPath = "C://Temp//uploads";
//			
//			Path rootPath = Paths.get("uploads").resolve(uniqueFileName);
//			Path absolutePath = rootPath.toAbsolutePath();
//			try {
//				
////				byte[] bytes = foto.getBytes();
////				Path rutaCompleta = Paths.get(rootPath + "//" + foto.getOriginalFilename());
////				Files.write(rutaCompleta, bytes);
//				
//				log.info("rootPath: " + rootPath);
//				log.info("absolutePath: " + absolutePath);
//				
//				Files.copy(foto.getInputStream(), absolutePath);
			String uniqueFileName = null;
			try {
				uniqueFileName = uploadFileService.copy(foto);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			flash.addFlashAttribute("info", "Has subido correctamente " + uniqueFileName);
			cliente.setFoto(uniqueFileName);
//			} catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
		}
		String msgFlash = (cliente.getId() == null ? "Cliente guardado." : "Cliente editado.");
		clienteService.save(cliente);
		status.setComplete();
		flash.addFlashAttribute("success", msgFlash);
		return "redirect:/listar";
	}
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/form/{id}")
	public String editarFormulario(@PathVariable(value = "id") Long id, RedirectAttributes flash,
			Map<String, Object> model) {
		Cliente cliente = null;
		if (id > 0) {
			cliente = clienteService.findOne(id);
			if (cliente == null) {
				flash.addFlashAttribute("error", "Cliente no encontrado.");
				return "redirect:/listar";
			}
		} else {
			flash.addFlashAttribute("error", "Cliente no encontrado.");
			return "redirect:/listar";
		}
		model.put("cliente", cliente);
		model.put("titulo", "Formulario Cliente");
		return "form";
	}

	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/eliminar/{id}")
	public String eliminarFormulario(@PathVariable(value = "id") Long id, RedirectAttributes flash) {
		if (id > 0) {
			Cliente cliente = clienteService.findOne(id);

			clienteService.delete(id);

			if (uploadFileService.delete(cliente.getFoto())) {
				flash.addFlashAttribute("info", "Archivo " + cliente.getFoto() + " eliminado correctamente.");
			}

		} else {
			flash.addFlashAttribute("error", "Cliente no encontrado.");
		}
		flash.addFlashAttribute("success", "Cliente eliminado.");
		return "redirect:/listar";
	}
	
	private boolean hasRole(String role) {
		SecurityContext context = SecurityContextHolder.getContext();
		if (context == null) {
			return false;
		}
		Authentication auth = context.getAuthentication();
		if (auth == null) {
			return false;
		}
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
//		for (GrantedAuthority grantedAuthority : authorities) {
//			if (role.equals(grantedAuthority.getAuthority())) {
//				logger.info("Hola "
//						.concat(auth.getName())
//						.concat(" tienes el rol ")
//						.concat(grantedAuthority.getAuthority()));
//				return true;
//			}
//		}
//		return false;
		
		return authorities.contains(new SimpleGrantedAuthority(role));
	}
}
