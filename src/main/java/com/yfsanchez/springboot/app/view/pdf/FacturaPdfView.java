package com.yfsanchez.springboot.app.view.pdf;

import java.awt.Color;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractPdfView;

import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.yfsanchez.springboot.app.models.entity.Factura;
import com.yfsanchez.springboot.app.models.entity.ItemFactura;

@Component("factura/ver")
public class FacturaPdfView extends AbstractPdfView{

	@Override
	protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer,
			HttpServletRequest request, HttpServletResponse response) throws Exception {
		
		MessageSourceAccessor message = getMessageSourceAccessor();
		Factura factura = (Factura)model.get("factura");
		
		PdfPTable tabla = new PdfPTable(1);
		PdfPCell cell = null;
		
		cell = new PdfPCell(new Phrase(message.getMessage("text.factura.ver.datos.cliente")));
		cell.setBackgroundColor(new Color(184, 218, 255));
		cell.setPadding(8f);
		tabla.addCell(cell);
		tabla.addCell(factura.getCliente().getNombre() + " " + factura.getCliente().getApellido());
		tabla.addCell(factura.getCliente().getEmail());
		tabla.setSpacingAfter(10);
		document.add(tabla);
		
		PdfPTable tabla2 = new PdfPTable(1);
		cell = new PdfPCell(new Phrase(message.getMessage("text.factura.ver.datos.factura")));
		cell.setBackgroundColor(new Color(184, 218, 255));
		cell.setPadding(8f);
		tabla2.addCell(cell);
		tabla2.addCell(message.getMessage("text.cliente.factura.folio")+ " : " + factura.getId());
		tabla2.addCell(message.getMessage("text.cliente.factura.descripcion")+ " : " + factura.getDescripcion());
		tabla2.addCell(message.getMessage("text.cliente.factura.fecha")+ " : " + factura.getCreatedAt());
		tabla2.setSpacingAfter(10);
		document.add(tabla2);
		
		PdfPTable tabla3 = new PdfPTable(4);
		tabla3.setWidths(new float [] {2.5f,1,1,1});
		tabla3.addCell(message.getMessage("text.factura.form.item.nombre"));
		tabla3.addCell(message.getMessage("text.factura.form.item.precio"));
		tabla3.addCell(message.getMessage("text.factura.form.item.cantidad"));
		tabla3.addCell(message.getMessage("text.factura.form.item.total"));
		for(ItemFactura item: factura.getItems()) {
			tabla3.addCell(item.getProducto().getNombre());
			cell = new PdfPCell(new Phrase(item.getProducto().getPrecio().toString()));
			cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
			tabla3.addCell(cell);
			
			cell = new PdfPCell(new Phrase(item.getCantidad().toString()));
			cell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
			tabla3.addCell(cell);
			
			cell = new PdfPCell(new Phrase(item.calcularImporte().toString()));
			cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
			tabla3.addCell(cell);
		}
		cell = new PdfPCell(new Phrase(message.getMessage("text.factura.form.total")));
		cell.setColspan(3);
		cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
		tabla3.addCell(cell);
		tabla3.addCell(factura.getTotal().toString());
		document.add(tabla3);
		
	}

}
