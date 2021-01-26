package com.yfsanchez.springboot.app.util.paginator;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Page;

public class PageRender<T> {
	private String url;
	private Page<T> page;
	
	private List<PageItem> pages;
	
	private int totalPages;
	private int numberElemntByPage;
	private int currentPage;

	public PageRender(String url, Page<T> page) {
		this.url = url;
		this.page = page;
		totalPages = page.getTotalPages();
		numberElemntByPage = page.getSize();
		currentPage = page.getNumber() + 1;
		
		pages = new ArrayList<PageItem>();
		
		int desde, hasta;
		if (totalPages <= numberElemntByPage) {
			desde = 1;
			hasta = totalPages;
		} else {
			if (currentPage <= numberElemntByPage/2) {
				desde = 1;
				hasta = numberElemntByPage;
			} else if (currentPage >= totalPages - numberElemntByPage/2) {
				desde = totalPages - numberElemntByPage + 1;
				hasta = numberElemntByPage;
			} else {
				desde = currentPage - numberElemntByPage/2;
				hasta = currentPage + numberElemntByPage/2;
			}
		}
		
		for (int i = 0; i < hasta; i++) {
			pages.add(new PageItem(desde + i, currentPage == desde + i));
			
		}
		
	}

	public String getUrl() {
		return url;
	}

	public List<PageItem> getPages() {
		return pages;
	}

	public int getTotalPages() {
		return totalPages;
	}

	public int getCurrentPage() {
		return currentPage;
	}
	
	public boolean isFirst() {
		return page.isFirst();
	}
	public boolean isLast() {
		return page.isLast();
	}
	public boolean hasNext() {
		return page.hasNext();
	}
	public boolean hasPrevious() {
		return page.hasPrevious();
	}
	
	
}
