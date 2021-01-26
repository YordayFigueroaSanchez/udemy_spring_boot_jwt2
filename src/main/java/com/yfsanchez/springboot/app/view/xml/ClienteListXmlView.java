package com.yfsanchez.springboot.app.view.xml;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.xml.MarshallingView;

import com.yfsanchez.springboot.app.models.entity.Cliente;

@Component("listar.xml")
public class ClienteListXmlView extends MarshallingView{
	
	

	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		model.remove("titulo");
		model.remove("page");
		Page<Cliente> clientes = (Page<Cliente>) model.get("clientes");
		model.remove("cliente");
		
		model.put("clienteList", new ClienteList(clientes.getContent()));
		
		super.renderMergedOutputModel(model, request, response);
	}

	@Autowired
	public ClienteListXmlView(Jaxb2Marshaller marshaller) {
		super(marshaller);
		// TODO Auto-generated constructor stub
	}
	
	

}
