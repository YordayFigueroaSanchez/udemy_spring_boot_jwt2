package com.yfsanchez.springboot.app.controllers;

import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.yfsanchez.springboot.app.models.entity.Cliente;
import com.yfsanchez.springboot.app.models.entity.Factura;
import com.yfsanchez.springboot.app.models.entity.ItemFactura;
import com.yfsanchez.springboot.app.models.entity.Producto;
import com.yfsanchez.springboot.app.models.service.IClienteService;
@Secured("ROLE_ADMIN")
@Controller
@RequestMapping("/factura")
@SessionAttributes("factura")
public class FacturaController {

	@Autowired
	private IClienteService clienteService;
	
	@GetMapping("/eliminar/{id}")
	public String eliminar(@PathVariable() Long id, RedirectAttributes messageFlash) {
		Factura factura = clienteService.findFacturaById(id);
		if (factura != null) {
			clienteService.deleteFactura(id);
			messageFlash.addFlashAttribute("success", "Factura eliminada.");
			return "redirect:/ver/" + factura.getCliente().getId();
		}
		messageFlash.addFlashAttribute("error", "Factura no encontrada.");
		return "redirect:/listar";
	}
	
	@GetMapping("/ver/{id}")
	public String ver(@PathVariable(value = "id") Long id, Model model, RedirectAttributes messageFlash) {
//		Factura factura = clienteService.findFacturaById(id);
		Factura factura = clienteService.fetchByIdWithClienteWitchItemFacturaWhithProducto(id);
		if (factura == null) {
			messageFlash.addFlashAttribute("error", "Factura no encontrada");
			return "refirect:/listar";
		}
		model.addAttribute("factura", factura);
		messageFlash.addFlashAttribute("titulo", "Factura".concat(factura.getDescripcion()));
		return "factura/ver";
	}
	
	@GetMapping("/form/{clienteId}")
	public String crear(@PathVariable(value = "clienteId") Long clienteId, 
			Map<String, Object> model, 
			RedirectAttributes messageFlash) {
		Cliente cliente = clienteService.findOne(clienteId);
		if (cliente == null) {
			messageFlash.addFlashAttribute("error", "Cliente no encontrado.");
			return "redirect:/listar ";
		}
		Factura factura = new Factura();
		factura.setCliente(cliente);
		
		model.put("factura", factura);
		model.put("titulo", "Crear Factura");
		return "factura/form";
	}
	@GetMapping(value = "/cargar-productos/{term}", produces={"application/json"})
	public @ResponseBody List<Producto> cargarProductos(@PathVariable String term){
		System.out.println(term);
		return clienteService.findByNombre(term);
	}
	@PostMapping("/form")
	public String guardar(@Valid Factura factura, BindingResult bindingResult, Model model,
			@RequestParam(name = "item_id[]", required = false) Long[] itemId,
			@RequestParam(name = "cantidad[]", required = false) Integer[] cantidad,
			RedirectAttributes msgFlash,
			SessionStatus status) {
		if (bindingResult.hasErrors()) {
			model.addAttribute("titulo", "Crear Factura");
			return "factura/form";
		}
		if (itemId == null || itemId.length == 0) {
			model.addAttribute("titulo", "Crear Factura");
			model.addAttribute("error", "La factura tiene que tener lineas.");
			return "factura/form";
		}
		for (int i=0; i<itemId.length; i++) {
			Producto producto = clienteService.findProductoById(itemId[i]);
			ItemFactura linea = new ItemFactura();
			linea.setCantidad(cantidad[i]);
			linea.setProducto(producto);
			factura.addItemFactura(linea);
		}
		clienteService.saveFactura(factura);
		status.setComplete();
		msgFlash.addFlashAttribute("success", "Factura guardada.");
		return "redirect:/ver/" + factura.getCliente().getId();
	}
}
