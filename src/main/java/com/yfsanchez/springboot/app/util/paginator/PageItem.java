package com.yfsanchez.springboot.app.util.paginator;

public class PageItem {
	
	private int numero;
	private boolean actual;
	
	public int getNumero() {
		return numero;
	}
	public boolean isActual() {
		return actual;
	}
	public PageItem(int numero, boolean actual) {
		this.numero = numero;
		this.actual = actual;
	}

	
	
}
