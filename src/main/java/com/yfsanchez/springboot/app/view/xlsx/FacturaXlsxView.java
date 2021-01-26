package com.yfsanchez.springboot.app.view.xlsx;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractXlsxView;

import com.yfsanchez.springboot.app.models.entity.Factura;
import com.yfsanchez.springboot.app.models.entity.ItemFactura;

@Component("factura/ver.xlsx")
public class FacturaXlsxView extends AbstractXlsxView{

	@Override
	protected void buildExcelDocument(Map<String, Object> model, Workbook workbook, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		MessageSourceAccessor message = getMessageSourceAccessor();
		response.setHeader("Content-Disposition", "attachmen; filename=\"factura.xlsx\"");
		Factura factura = (Factura) model.get("factura");
		Sheet sheet = workbook.createSheet("Factura");
		
		Row row = sheet.createRow(0);
		Cell cell = row.createCell(0);
		cell.setCellValue(message.getMessage("text.factura.ver.datos.cliente"));
		
		row = sheet.createRow(1);
		cell = row.createCell(0);
		cell.setCellValue(factura.getCliente().getNombre()+" "+factura.getCliente().getApellido());
		
		row = sheet.createRow(2);
		cell = row.createCell(0);
		cell.setCellValue(factura.getCliente().getEmail());
		
		sheet.createRow(4).createCell(0).setCellValue(message.getMessage("text.factura.ver.datos.factura"));
		row = sheet.createRow(5);
		row.createCell(0).setCellValue(message.getMessage("text.cliente.factura.folio"));
		row.createCell(1).setCellValue(factura.getId());
		row = sheet.createRow(6);
		row.createCell(0).setCellValue(message.getMessage("text.cliente.factura.descripcion"));
		row.createCell(1).setCellValue(factura.getDescripcion());
		row = sheet.createRow(7);
		row.createCell(0).setCellValue(message.getMessage("text.cliente.factura.fecha"));
		row.createCell(1).setCellValue(factura.getCreatedAt());
		CellStyle theaderStyle = workbook.createCellStyle();
		theaderStyle.setBorderBottom(BorderStyle.MEDIUM);
		theaderStyle.setBorderTop(BorderStyle.MEDIUM);
		theaderStyle.setBorderLeft(BorderStyle.MEDIUM);
		theaderStyle.setBorderRight(BorderStyle.MEDIUM);
		theaderStyle.setFillForegroundColor(IndexedColors.GOLD.index);
		theaderStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
		
		CellStyle tbodyStyle = workbook.createCellStyle();
		tbodyStyle.setBorderBottom(BorderStyle.THIN);
		tbodyStyle.setBorderTop(BorderStyle.THIN);
		tbodyStyle.setBorderLeft(BorderStyle.THIN);
		tbodyStyle.setBorderRight(BorderStyle.THIN);
		
		Row header = sheet.createRow(9);
		header.createCell(0).setCellValue(message.getMessage("text.factura.form.item.nombre"));
		header.getCell(0).setCellStyle(theaderStyle);
		header.createCell(1).setCellValue(message.getMessage("text.factura.form.item.precio"));
		header.getCell(1).setCellStyle(theaderStyle);
		header.createCell(2).setCellValue(message.getMessage("text.factura.form.item.cantidad"));
		header.getCell(2).setCellStyle(theaderStyle);
		header.createCell(3).setCellValue(message.getMessage("text.factura.form.item.total"));
		header.getCell(3).setCellStyle(theaderStyle);
		
		int rownum = 10;
		for (ItemFactura item : factura.getItems()) {
			Row fila = sheet.createRow(rownum++);
			cell = fila.createCell(0);
			cell.setCellValue(item.getProducto().getNombre());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(1);
			cell.setCellValue(item.getProducto().getPrecio());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(2);
			cell.setCellValue(item.getCantidad());
			cell.setCellStyle(tbodyStyle);
			
			cell = fila.createCell(3);
			cell.setCellValue(item.calcularImporte());
			cell.setCellStyle(tbodyStyle);
		}	
		Row total = sheet.createRow(rownum);
		total.createCell(0).setCellValue(message.getMessage("text.factura.form.total"));
		total.createCell(3).setCellValue(factura.getTotal());
		
		
		
	}

}
