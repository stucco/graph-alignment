package alignment.alignment_v2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.UUID;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.text.*;

import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.extensions.vulnerability.CVRF11InstanceType;
import org.mitre.stix.exploittarget_1.AffectedSoftwareType;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.cybox.objects.Product;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.common_2.ObjectPropertiesType;
import org.mitre.stix.common_1.RelatedObservableType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.stix.common_1.ReferencesType;
import org.mitre.stix.common_1.InformationSourceType;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.common_1.RelatedCourseOfActionType;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.cybox.common_2.TimeType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException; 
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.*;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Element;
import org.w3c.dom.Entity;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;	

public class PreprocessSTIX {

	
	
	public static Document parseXMLText(String documentText){
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
		DocumentBuilder db;
		Document doc = null;
		try {
			db = dbf.newDocumentBuilder();
			InputSource inputSource = new InputSource( new StringReader( documentText ) );
			doc = db.parse(inputSource);
		} catch (ParserConfigurationException e) {
			// TODO handle
			e.printStackTrace();
			return null;
		} catch (SAXException  e) {
			// TODO handle
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			// TODO handle
			e.printStackTrace();
			return null;
		}
		return doc;
	}
	
	
	//public interface.  Takes any valid STIX, and converts it to Titan-friendly GraphSON.
	public static JSONObject preprocessSTIX(String STIXString){
		try {
			Document initialDoc = parseXMLText(STIXString);
			Document normalizedDoc = normalizeSTIX(initialDoc);
			JSONObject graph = generateGRAPHson(normalizedDoc);
			return graph;
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	//TODO: "normalize" by removing child items where needed, and replacing with idrefs
	//do this until there are only "basic-enough" types remaining, associated with idrefs
	static Document normalizeSTIX(Document initialDoc) throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
        DocumentBuilder builder;
        Document newDocument = null;
        
        builder = dbf.newDocumentBuilder();
		newDocument = builder.newDocument();
		Element newRoot = newDocument.createElement("stix:STIX_Package");
		newDocument.appendChild(newRoot);
		
		//TODO: need to break off child nodes, re-add with idrefs
		
		return newDocument;
	}
	
	//TODO: convert each known "basic" type to a vertex, and each idref to an edge.
	static JSONObject generateGRAPHson(Document normalizedSTIXContent) {
		// TODO Auto-generated method stub
		return null;
	}

	static boolean validate(STIXPackage stixPackage) {
		try	{
			return stixPackage.validate();
		}			
		catch (SAXException e)	{
			e.printStackTrace();
		}
		return false;
	}
	
}
