package com.yfsanchez.springboot.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.yfsanchez.springboot.app.models.dao.IClienteDaoCrudRepository;
import com.yfsanchez.springboot.app.models.dao.IFacturaDao;
import com.yfsanchez.springboot.app.models.dao.IProductoDao;
import com.yfsanchez.springboot.app.models.entity.Cliente;
import com.yfsanchez.springboot.app.models.entity.Factura;
import com.yfsanchez.springboot.app.models.entity.Producto;

@Service
public class ClienteServiceImpl implements IClienteService {

	@Autowired
//	IClienteDao clienteDao;
	private IClienteDaoCrudRepository clienteDao;
	
	@Autowired
	private IProductoDao productoDao;
	
	@Autowired
	private IFacturaDao facturaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Cliente> findAll() {
		// TODO Auto-generated method stub
//		return clienteDao.findAll();
		return (List<Cliente>) clienteDao.findAll();
	}

	@Override
	@Transactional
	public void save(Cliente cliente) {
		// TODO Auto-generated method stub
		clienteDao.save(cliente);
		
	}

	@Override
	@Transactional(readOnly = true)
	public Cliente findOne(Long id) {
		// TODO Auto-generated method stub
//		return clienteDao.findOne(id);
		return clienteDao.findById(id).orElse(null);
	}

	@Override
	@Transactional
	public void delete(Long id) {
		// TODO Auto-generated method stub
//		clienteDao.delete(id);
		clienteDao.deleteById(id);
	}

	@Override
	@Transactional(readOnly = true)
	public Page<Cliente> findAll(Pageable pageable) {
		// TODO Auto-generated method stub
		return clienteDao.findAll(pageable);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Producto> findByNombre(String term) {
		// TODO Auto-generated method stub
//		return productoDao.findByNombre(term);
		return productoDao.findByNombreLikeIgnoreCase("%"+term+"%");
	}

	@Override
	@Transactional
	public void saveFactura(Factura factura) {
		facturaDao.save(factura);
		
	}

	@Override
	@Transactional(readOnly = true)
	public Producto findProductoById(Long id) {
		// TODO Auto-generated method stub
		return productoDao.findById(id).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public Factura findFacturaById(Long id) {
		// TODO Auto-generated method stub
		return facturaDao.findById(id).orElse(null);
	}

	@Override
	public void deleteFactura(Long id) {
		facturaDao.deleteById(id);
		
	}

	@Override
	@Transactional(readOnly = true)
	public Factura fetchByIdWithClienteWitchItemFacturaWhithProducto(Long id) {
		// TODO Auto-generated method stub
		return facturaDao.fetchByIdWithClienteWitchItemFacturaWhithProducto(id);
	}

	@Override
	@Transactional(readOnly = true)
	public Cliente fetchByIdWithFacturas(Long id) {
		// TODO Auto-generated method stub
		return clienteDao.fetchByIdWithFacturas(id);
	}

}
