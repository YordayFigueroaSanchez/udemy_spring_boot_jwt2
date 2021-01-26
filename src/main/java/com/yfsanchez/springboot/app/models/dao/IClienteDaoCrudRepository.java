package com.yfsanchez.springboot.app.models.dao;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

import com.yfsanchez.springboot.app.models.entity.Cliente;

//public interface IClienteDaoCrudRepository extends CrudRepository<Cliente, Long>{
public interface IClienteDaoCrudRepository extends PagingAndSortingRepository<Cliente, Long>{
	
	@Query("select c from Cliente c left join  c.facturas f where c.id=?1")
	public Cliente fetchByIdWithFacturas(Long id);

}
