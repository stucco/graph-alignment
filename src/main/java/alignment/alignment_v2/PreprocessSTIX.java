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

	//"sort" the top-level elements of this STIX document (eg. so they can be more easily compared.)
	static Document sortXML(Document initialDoc) throws ParserConfigurationException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
        DocumentBuilder builder;
        Document newDocument = null;
        
        builder = dbf.newDocumentBuilder();
		newDocument = builder.newDocument();
		Element newRoot = newDocument.createElement("stix:STIX_Package");
		newDocument.appendChild(newRoot);
		
		//build the initial list of nodes to handle
		//NodeList nodes = initialDoc.getChildNodes();
		NodeList nodes = initialDoc.getFirstChild().getChildNodes();
		if(nodes == null){ //if you never had any nodes, just return what you had.
			return initialDoc;
		}
		int nodeCount = nodes.getLength();
		List<Node> nodesToHandle = new ArrayList<Node>(nodeCount);
		List<String> nodeStringsToHandle = new ArrayList<String>(nodeCount);
		for(int i=0; nodes != null && i<nodeCount; i++){
			//go ahead and make a new copy of these nodes, so they're associated with the new document, to save hassle later.
			Node node = newDocument.importNode(nodes.item(i), true);
			//skip empty text nodes.
			if(isEmptyNode(node)){
				continue;
			}
			nodesToHandle.add(node);
			nodeStringsToHandle.add(nodeToString(node));
		}
		
		//TODO: this is just a really crappy bubble sort.  But leaving it for now, since this is currently only used in the unit tests.
		boolean sorted = false;
		while(!sorted){
			sorted = true;
			for(int i=1; i<nodeCount; i++){
				if( nodeStringsToHandle.get(i-1).compareTo(nodeStringsToHandle.get(i)) > 0){
					sorted = false;
					String tempString = nodeStringsToHandle.get(i-1);
					nodeStringsToHandle.set(i-1, nodeStringsToHandle.get(i));
					nodeStringsToHandle.set(i, tempString);
					Node tempNode = nodesToHandle.get(i-1);
					nodesToHandle.set(i-1, nodesToHandle.get(i));
					nodesToHandle.set(i, tempNode);
				}
			}
		}
		
		//and now, put the nodes into the new document.
		for(int i=0; nodes != null && i<nodeCount; i++){
			Node curr = nodesToHandle.get(i);
			newRoot.appendChild(curr);
		}
		
		//copy attributes of root node.
		NamedNodeMap attrs = initialDoc.getFirstChild().getAttributes();
		for(int i=0; attrs != null && i<attrs.getLength(); i++){
			Attr attr = (Attr) newDocument.importNode(attrs.item(i), true);
			//newRoot.appendChild(attr);
			newRoot.setAttribute(attr.getName(), attr.getValue());
		}
		
		return newDocument;
	}
	
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
	
	//wow. Something so basic ends up like this.  see: https://stackoverflow.com/a/5456836
	public static String XMLToString(Document doc){
		((Element)doc.getFirstChild()).setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer;
		String output = null;
		try {
			transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			output = writer.getBuffer().toString().replaceAll("\n|\r", "");
		} catch (TransformerConfigurationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (TransformerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return output;
	}
	
	//this is kind of hacky, and likely slow.  use for debugging only.
	private static String nodeToString(Node node){
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
        DocumentBuilder builder;
        Document newDocument = null;
		try {
			builder = dbf.newDocumentBuilder();
			newDocument = builder.newDocument();
			//Element elementCopy = (Element)element.cloneNode(true);
			Node nodeCopy = newDocument.importNode(node, true);
			
			Element newRoot = newDocument.createElement("temp");
			newDocument.appendChild(newRoot);
			newRoot.appendChild(nodeCopy);

			return XMLToString(newDocument);
		}catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	private static boolean isEmptyNode(Node n){
		if(n.getNodeType() == Node.TEXT_NODE){
			String text = n.getNodeValue();
			if(text.replace(" ", "").equals("")){
				return true;
			}
		}
		return false;
	}
	
	//public interface.  Takes any valid STIX, and converts it to Titan-friendly GraphSON.
	public static JSONObject preprocessSTIX(String STIXString){
		try {
			Document initialDoc = parseXMLText(STIXString);
			Document normalizedDoc = normalizeSTIX(initialDoc);
			Document finishedDoc = flattenSTIX(normalizedDoc);
			JSONObject graph = generateGRAPHson(finishedDoc);
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
	
	
	//Titan doesn't handle vertices with Object type values well.
	//At this point, the document should be normalized, and items should be simple enough that we can just flatten them here.
	static Document flattenSTIX(Document initialDoc) throws ParserConfigurationException {
		//System.out.println("flattening document: " + XMLToString(initialDoc));
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(false);
        DocumentBuilder builder;
        Document newDocument = null;

		builder = dbf.newDocumentBuilder();
		newDocument = builder.newDocument();
		Element newRoot = newDocument.createElement("stix:STIX_Package");
		newDocument.appendChild(newRoot);
		//System.out.println("created new document: " + XMLToString(newDocument));
		
		//handle attributes of root node.
		NamedNodeMap attrs = initialDoc.getFirstChild().getAttributes();
		for(int i=0; attrs != null && i<attrs.getLength(); i++){
			Attr attr = (Attr) newDocument.importNode(attrs.item(i), true);
			//newRoot.appendChild(attr);
			newRoot.setAttribute(attr.getName(), attr.getValue());
		}
		
		//build the initial list of nodes to handle
		//NodeList nodes = initialDoc.getChildNodes();
		NodeList nodes = initialDoc.getFirstChild().getChildNodes();
		List<Node> nodesToHandle = new LinkedList<Node>();
		for(int i=0; nodes != null && i<nodes.getLength(); i++){
			//go ahead and make a new copy of these nodes, so they're associated with the new document, to save hassle later.
			Node node = newDocument.importNode(nodes.item(i), true);
			//skip empty text nodes.
			if(isEmptyNode(node)){
				continue;
			}
			nodesToHandle.add(node);
		}
		
		//handle everything in the list as needed.
		boolean done = false;
		while(!done){
			List<Node> nextNodesToHandle = new LinkedList<Node>();
			for(Node n : nodesToHandle){
				//skip empty text nodes.
				if(isEmptyNode(n)){
					continue;
				}
				short nTypeCode = n.getNodeType();
				
				//handle attributes of the current node
				NamedNodeMap currAttrs = n.getAttributes();
				for(int i=0; currAttrs != null && i<currAttrs.getLength(); i++){
					//System.out.println("handling attributes of element: " + nodeToString(n));
					Attr attr = (Attr) newDocument.importNode(currAttrs.item(i), true);
					//n.removeChild(attr);
					//newRoot.setAttribute(attr.getName(), attr.getValue());
					String tagName = n.getNodeName() + "--" + attr.getName(); //getNodeName returns the tag name, if the node is an element node.
					Element newElement = newDocument.createElement(tagName);
					//newElement.setNodeValue(attr.getValue());
					Node text = newDocument.createTextNode(attr.getValue());
					newElement.appendChild(text);
					//System.out.println("created new element: " + nodeToString(newElement));
					newRoot.appendChild(newElement);
					//System.out.println("modified the new document (3): " + XMLToString(newDocument));
				}
				
				
				//add this node if appropriate
				if(!(n.hasChildNodes())){
					newRoot.appendChild(n);
					//System.out.println("modified the new document (1): " + XMLToString(newDocument));
				}else if(n.getChildNodes().getLength() == 1 && n.getFirstChild().getNodeType() == Node.TEXT_NODE){
					newRoot.appendChild(n);
					//System.out.println("modified the new document (2): " + XMLToString(newDocument));
				}else{ //and now handle the child nodes, by promoting them into the list for next time.
					NodeList childNodes = n.getChildNodes();
					for(int i=0; i<childNodes.getLength(); i++){
						//Node newNode = n.cloneNode(false);
						Node currChild = childNodes.item(i);
						short currChildTypeCode = currChild.getNodeType();
						//System.out.println("child node " + nodeToString(currChild));
						if(currChildTypeCode == Node.ELEMENT_NODE){
							String tagName = n.getNodeName() + "--" + currChild.getNodeName(); //getNodeName returns the tag name, if the node is an element node.
							
							Element newElement = newDocument.createElement(tagName);
							//System.out.println("created new element: " + nodeToString(newElement));
							
							//NamedNodeMap childAttrs = currChild.getAttributes();
							//for(int j=0; childAttrs != null && j<childAttrs.getLength(); j++){
							//	Attr attr = (Attr) newDocument.importNode(childAttrs.item(j), true);
							//	newElement.setAttribute(attr.getName(), attr.getValue());
							//}
							//handle attributes of the current node
							//NamedNodeMap currAttrs = n.getAttributes();
							NamedNodeMap childAttrs = currChild.getAttributes();
							for(int j=0; childAttrs != null && j<childAttrs.getLength(); j++){
								//System.out.println("handling attributes of element: " + nodeToString(n));
								Attr attr = (Attr) newDocument.importNode(childAttrs.item(j), true);
								//n.removeChild(attr);
								//newRoot.setAttribute(attr.getName(), attr.getValue());
								String tagName2 = n.getNodeName() + "--" + currChild.getNodeName() + "--" + attr.getName(); //getNodeName returns the tag name, if the node is an element node.
								Element newElement2 = newDocument.createElement(tagName2);
								//newElement.setNodeValue(attr.getValue());
								Node text = newDocument.createTextNode(attr.getValue());
								newElement2.appendChild(text);
								//System.out.println("created new element: " + nodeToString(newElement2));
								newRoot.appendChild(newElement2);
								//System.out.println("modified the new document (3): " + XMLToString(newDocument));
							}
							
							NodeList gChildNodes = currChild.getChildNodes();
							//TODO: confirm that moving nodes below doesn't screw with the NodeList state.
							for(int j=0; j<gChildNodes.getLength(); j++){
								Node gChild = gChildNodes.item(j);
								if(isEmptyNode(gChild)){
									continue;
								}
								newElement.appendChild(gChild);
							}
							nextNodesToHandle.add(newElement);
						}else{//TODO else (properly) handle other types as needed
							//System.out.println("Element type is: " + currChildTypeCode);
							nextNodesToHandle.add(currChild);
							//newRoot.appendChild(currChild);
							//System.out.println("modified the new document (3): " + XMLToString(newDocument));
						}
					}
				}
			}
			if(nextNodesToHandle.size() == 0){
				done = true;
			}else{
				nodesToHandle = nextNodesToHandle;
			}
		}
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
