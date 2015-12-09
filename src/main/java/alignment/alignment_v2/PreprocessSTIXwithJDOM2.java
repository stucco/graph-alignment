package alignment.alignment_v2;

import javax.xml.namespace.QName;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.SortedSet;
import java.util.Set;
import java.util.HashSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.Collections;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.StringReader;
import java.io.IOException;
import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jdom2.output.XMLOutputter;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.AttributeType;
import org.jdom2.Content;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.xpath.*;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.stix_1.TTPsType;
import org.mitre.stix.common_1.TTPBaseType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;

import org.mitre.stix.incident_1.Incident;
import org.mitre.stix.common_1.IncidentBaseType;
import org.mitre.stix.stix_1.IncidentsType;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.stix_1.CoursesOfActionType;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.campaign_1.Campaign;
import org.mitre.stix.stix_1.CampaignsType;
import org.mitre.stix.common_1.CampaignBaseType;
import org.mitre.stix.threatactor_1.ThreatActor;
import org.mitre.stix.stix_1.ThreatActorsType;
import org.mitre.stix.common_1.ThreatActorBaseType;
import org.mitre.stix.report_1.Report;
import org.mitre.stix.stix_1.RelatedPackageType;

import java.math.BigInteger;
import java.math.BigDecimal;

import java.lang.Class;
import java.lang.reflect.Field;
import java.lang.IllegalAccessException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.NoSuchMethodException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PreprocessSTIXwithJDOM2 {

	private static final Logger logger = LoggerFactory.getLogger(PreprocessSTIXwithJDOM2.class);

	private Document stixDocument = null;
	private int count;
	private static final Namespace stixNS = Namespace.getNamespace("stix", "http://stix.mitre.org/stix-1");
	private static final Namespace xsiNS = Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
	private static final Map<String, Integer> comparisonMap;
	private static final Map<String, String> parentElementMap;
	private static final Map<String, Element> stixElementMap;
	private static final Set<String> stixElementSet;
	static {
		Set<String> stixSet = new HashSet<String>();
		stixSet.add("stix:Observables");
		stixSet.add("stix:Indicators");
		stixSet.add("stix:TTPs");
		stixSet.add("stix:Exploit_Targets");
		stixSet.add("stix:Incidents");
		stixSet.add("stix:Courses_Of_Action");
		stixSet.add("stix:Campaigns");
		stixSet.add("stix:Threat_Actors");
		stixElementSet = Collections.unmodifiableSet(stixSet);

		/* mapping element to proper parent element */
		Map<String, String> map = new HashMap<String, String>();		
		map.put("Observable", "Observables");
		map.put("Indicator", "Indicators");
		map.put("TTP", "TTPs");
		map.put("Exploit_Target", "Exploit_Targets");
		map.put("Incident", "Incidents");
		map.put("Course_Of_Action", "Courses_Of_Action");
		map.put("Campaign", "Campaigns");
		map.put("Threat_Actor", "Threat_Actors");
		map.put("Report", "Reports");
		map.put("Related_Package", "Related_Packages");
		parentElementMap = Collections.unmodifiableMap(map);
		
		/* mapping element name to jdom Element */
		// precomputed to avoid extra string comparisons */
		Map<String, Element> initElementMap = new HashMap<String, Element>();		
		initElementMap.put("Observable", new Element("Observable", "cybox", "http://cybox.mitre.org/cybox-2"));
		initElementMap.put("Indicator", new Element("Indicator", stixNS));
		initElementMap.put("TTP", new Element("TTP", stixNS));
		initElementMap.put("Exploit_Target", new Element("Exploit_Target", "stixCommon", "http://stix.mitre.org/common-1"));
		initElementMap.put("Incident", new Element("Incident", stixNS));
		initElementMap.put("Course_Of_Action", new Element("Course_Of_Action", stixNS));
		initElementMap.put("Campaign", new Element("Campaign", stixNS));
		initElementMap.put("Threat_Actor", new Element("Threat_Actor", stixNS));
		stixElementMap = Collections.unmodifiableMap(initElementMap);
		
		/* map to support STIXComparator */
		Map<String, Integer> enumMap = new HashMap<String, Integer>();
		enumMap.put("stix:STIX_Header", 0);
		enumMap.put("stix:Observables", 1);
		enumMap.put("stix:Indicators", 2);
		enumMap.put("stix:TTPs", 3);
		enumMap.put("stix:Exploit_Targets", 4);
		enumMap.put("stix:Incidents", 5);
		enumMap.put("stix:Courses_Of_Action", 6);
		enumMap.put("stix:Campaigns", 7);
		enumMap.put("stix:Threat_Actors", 8);
		enumMap.put("stix:Reports", 9);
		enumMap.put("stix:Related_Packages", 10);
		comparisonMap = Collections.unmodifiableMap(enumMap);
	}

	/**
	 * Returns parentElementMap for testing only
	 */
	public Map<String, String> getParentElementMap() {
		return parentElementMap;
	}

	/**
	 * Returns stixElementMap for testing only
	 */
	public Map<String, Element> getStixElementMap() {
		return stixElementMap;
	}

	/**
	 * Function is required for sorting elements of stixPackage, or it would be invalid 
	 * @return int the outcome of compareTo function
	*/
	private class STIXComparator implements Comparator<Element> {
		public int compare(Element e1, Element e2) {
			return comparisonMap.get(e1.getQualifiedName()).compareTo(comparisonMap.get(e2.getQualifiedName()));
		}	
	}

	/**
	 * Funtion to get Document stixDoc as STIXPackage after normalizing
	 * @return STIXPackage normalized stix document
	*/
	public STIXPackage getSTIXPackage() {
		return STIXPackage.fromXMLString(new XMLOutputter().outputString(stixDocument));
	}

	/**
	 * Function to return Document stixDoc
	 * @return stixDoc jdom2 Document of stixPackage
	*/
	public Document getSTIXDocument() {
		return stixDocument;
	}

	/**
	 * Parses xml String and converts it to jdom2 Document
	 * @param documentText xml String 
	 * @return document xml of jdom2 Document type 
	*/ 
	public Document parseXMLText(String documentText) {
		try {
			SAXBuilder saxBuilder = new SAXBuilder();
			Document document = saxBuilder.build(new StringReader(documentText));
			return document;

		} catch (JDOMException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Prints jdom element 
	 */
	void printElement(Element element) {
		XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
		System.out.println(outputter.outputString(element));
	}

	/**
	* Prints stixPackage from stix string (useful for debugging)
	* @param stix stix document as String
	*/ 
	private void print(String stix) {
		STIXPackage testPackage = STIXPackage.fromXMLString(stix);
		System.out.println(testPackage.toXMLString(true));
	}

	/**
	* Normalizes (refactors) stix core elements (Observable, Indicator, COA, etc ...) 
	* by cloning content, appending it to the proper parent element, and adding reference to it from its original location
	* @param stixString stix package of type String
	*/
	public void normalizeSTIXPackage(String stixString) {
		stixDocument = parseXMLText(stixString);
		Element rootElement = stixDocument.getRootElement();
		Map<String, List<Element>> elementMap = traverseSTIXElements(rootElement, new HashMap<String, List<Element>>());

		if (elementMap.containsKey("Observable")) {
			Element observables = null;
			if (rootElement.getChild("Observables", stixNS) == null) {
				observables = new Element("Observables", stixNS);
				observables.setAttribute("cybox_minor_version", "1.0");
				observables.setAttribute("cybox_major_version", "2.0");
				rootElement.addContent(observables);
			} else {
				observables = rootElement.getChild("Observables", stixNS);
			}
			List<Element> elementList = elementMap.get("Observable");
			for (Element element : elementList) {
				observables.addContent(element);
			}
			elementMap.remove("Observable");
		}
		for (String key : elementMap.keySet()) {
			normalizeSTIXHelper(rootElement, key, elementMap.get(key));
		}
                 
		rootElement.sortChildren(new STIXComparator());
	}									

	/**
	* Creates proper parent elements (if such do not exist) for referenced elements and appending referenced elements to it
	* @param rootElement root element of stix package; used to loock for proper parent element
	* @param name name(tag) of referenced element (the one that should be appended)
	* @param elementList List of referenced elements with the same name (tag) and the same parent element
	*/
	private void normalizeSTIXHelper(Element rootElement, String name, List<Element> elementList) {
		Element parentElement = null;
		if (rootElement.getChild(parentElementMap.get(name), stixNS) == null) {
			parentElement = new Element(parentElementMap.get(name), stixNS);
			rootElement.addContent(parentElement);
		} else {
			parentElement = rootElement.getChild(parentElementMap.get(name), stixNS);
		}

		for (Element element : elementList) {
			parentElement.addContent(element);
		}
	}
	
	/** 
	* Traverses stix elements to find the one that should be moved out and referenced
	* @param element the element that will be traversed
	* @param elementMap contains found elements that should be referenced; key - element name, value - list of elements with the same name
	* @return elementMap edited elementMap 
	*/	
	private HashMap traverseSTIXElements(Element element, HashMap<String, List<Element>> elementMap) {
		if (stixElementSet.contains(element.getQualifiedName())) {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				if (child.getAttribute("id") == null) {
					child.setAttribute(new Attribute("id", child.getName() + "-" + UUID.randomUUID().toString()));
				}
				List<Element> grandChildrenList = child.getChildren();
				for (Element grandChild : grandChildrenList) {
					traverseSTIXElements(grandChild, elementMap);
				}
			}
		} else {
			String name = element.getName();
			if (stixElementMap.containsKey(name) && element.getAttribute("idref") == null) {	
				if (name.equals("Observable") || element.getAttribute("type", xsiNS) != null) {
					Element newElement = setNewElement(element);
					List<Element> elementList = (elementMap.containsKey(name)) ? elementMap.get(name) : new ArrayList<Element>();
					elementList.add(newElement);
					elementMap.put(name, elementList);
					List<Element> children = newElement.getChildren();
					for (Element child : children) {
						traverseSTIXElements(child, elementMap);
					}
				}
			}
			List<Element> children = element.getChildren();
			for (Element child : children) {
				traverseSTIXElements(child, elementMap);	
			}
		}
		return elementMap;
	}

	/**
	 * Copies the content of element into newElement, removing content, and adding reference to newElement 
	 * @param element contains content that should be copied
	 * @return newElement new referenced element
	 */
	private Element setNewElement(Element element) {
		String name = element.getName();
		Attribute id = null;
		if (element.getAttribute("id") != null) {
			id = element.getAttribute("id");
			element.removeAttribute("id");
		} else {
			id = new Attribute("id", name + "-" + UUID.randomUUID().toString()); 
		}
		Element newElement = element.clone();
		newElement.setNamespace(stixElementMap.get(name).getNamespace());
		newElement.setAttribute(id);
		element.setAttribute(new Attribute("idref", id.getValue()));
		element.removeContent();
		
		return newElement;
	}

	/**
	 * Converts xml document to JSON
	 * @return returns json representation of earlier initialized stix document, or null if document was not initialized
	 */
	public JSONObject xmlToJson() {
		return (stixDocument == null) ? null : xmlToJson(new XMLOutputter().outputString(stixDocument));
	}

	/**
	 * Converts xml document to JSON
	 * @return returns json representation of xmlString
	 */
	public JSONObject xmlToJson(String xmlString) {
		JSONObject stixJson = new JSONObject();
		JSONObject newObject = new JSONObject();
		JSONArray nsArray = new JSONArray();
		JSONArray attrArray = new JSONArray();
		Document xmlDoc = parseXMLText(xmlString);
		Element rootElement = xmlDoc.getRootElement();
		
		Namespace ns = rootElement.getNamespace();
		/* starting to create json version of root element by adding ns */
		if (!ns.getPrefix().isEmpty()) {
			newObject.put("ns", new JSONObject().put(ns.getPrefix(), ns.getURI()));
		}
		/* ... continue by adding attributes */
		List<Attribute> attributeList = rootElement.getAttributes();
		for (Attribute attr : attributeList) {
			JSONObject attrObject = new JSONObject();
			Namespace attrNs = attr.getNamespace();
			if (!attrNs.getPrefix().isEmpty()) {
				attrObject.put("ns", new JSONObject().put(attrNs.getPrefix(), attrNs.getURI()));
			}
			attrObject.put("content", attr.getValue());
			attrArray.put(new JSONObject().put(attr.getQualifiedName(), attrObject));
		}
		if (attrArray.length() != 0) {
			newObject.put("attr", attrArray);
		}
		List<Element> children = rootElement.getChildren();
		/* starting recursively traverse children to convert them to json */
		for (Element child : children) {
			elementToJson(child, newObject);
		}
		stixJson.put(rootElement.getName(), newObject);

		return stixJson;
	}
	
	/**
	 * Converts Element to jsonObject 
	 * @param element to be coverted
	 * @param stixJson json object to adit with element's content
	 */
	void elementToJson(Element element, JSONObject stixJson) {
		XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
		
		JSONArray nsArray = new JSONArray();
		JSONArray attrArray = new JSONArray();
		JSONObject newObject = new JSONObject();
		
		Namespace ns = element.getNamespace();
		/* copying ns */
		if (!ns.getPrefix().isEmpty()) {
			newObject.put("ns", new JSONObject().put(ns.getPrefix(), ns.getURI()));
		}

		/* copying attributes */
		List<Attribute> attributeList = element.getAttributes();
		for (Attribute attr : attributeList) {
			JSONObject attrObject = new JSONObject();
			Namespace attrNs = attr.getNamespace();
			if (!attrNs.getPrefix().isEmpty()) {
				attrObject.put("ns", new JSONObject().put(attrNs.getPrefix(), attrNs.getURI()));
			}
			attrObject.put("content", attr.getValue());
			attrArray.put(new JSONObject().put(attr.getQualifiedName(), attrObject));
		}
		if (attrArray.length() != 0) {
			newObject.put("attr", attrArray);
		}

		String content = element.getTextNormalize();
		if (!content.isEmpty()) {				
			newObject.put("content", content);
		} 
		
		/* if element contains children, recurcively traversing them */
		List<Element> children = element.getChildren();
		for (Element child : children) {
			elementToJson(child, newObject);
		}
						
		/* if element contains text, add it */				
		if (stixJson.has(element.getName())) { 
			/* if it is a new name for the existing json, adding content as a JSONObject*/					
			if (stixJson.get(element.getName()) instanceof JSONObject) {
				JSONObject object = stixJson.getJSONObject(element.getName());
				JSONArray array = new JSONArray();
				array.put(object);
				array.put(newObject);
				stixJson.put(element.getName(), array);
			} else {
				/* if element with the same name already exist, convert it to JSONArray */
				if (stixJson.get(element.getName()) instanceof JSONArray) {
					JSONArray array = stixJson.getJSONArray(element.getName());
					array.put(newObject);
					stixJson.put(element.getName(), array);
				} 
			}							
		} else {	
			stixJson.put(element.getName(), newObject);
		}
	}

	/**
	 * Parses and converts stixXml to Document and passes it to xmlToGraphson function
	 * @param stixXml stixPackage of type String that should be converted
	 * @return stixGraphson	graphson representation of stixXml  
	 */
	public JSONObject xmlToGraphson(String stixXml) {
		if (!validate(STIXPackage.fromXMLString(stixXml))) {
			logger.warn("Invalid STIXPackage");
		}
		stixDocument = parseXMLText(stixXml);
		return xmlToGraphson();
	}

	/**	
	 * Converts value of global variable stixDocument to Graphson by treating element's path as graphson keys
	 * and element's namespace, attributes, and text as values
	 * @return stixGraphson	graphson representation of stixXml  
	 */
	public JSONObject xmlToGraphson() {
		if (stixDocument == null) {
			return null;
		}

		JSONObject stixGraphson = new JSONObject();
		JSONArray vertices = new JSONArray();
		JSONArray edges = new JSONArray();

		Element rootElement = stixDocument.getRootElement();
		List<Element> elementList = rootElement.getChildren();

		count = 0;
		JSONObject rootVertex = setVertexJSONObject(rootElement, new JSONObject());
		rootVertex.put("_id", getElementId(rootElement));
		rootVertex.put("_type", "vertex");
		rootVertex.put("vertexType", "STIX_Package");

		for (Element element : elementList) {
			if (stixElementSet.contains(element.getQualifiedName())) {
				count  = 0;
				JSONObject vertex = setVertexJSONObject(element, new JSONObject());
				List<Element> elementList2 = element.getChildren();
				int newCount = count;
				for (Element element2 : elementList2) {
					count = newCount;
					JSONObject vertex2 = setVertexJSONObject(element2, new JSONObject(vertex.toString()));
					vertex2.put("_id", getElementId(element2));
					vertex2.put("_type", "vertex");
					vertex2.put("vertexType", element2.getName());
					traverseSTIXElements(element2, vertex2, edges);
					vertices.put(vertex2);
				}
			} else {
				count = 0;
				JSONObject vertex = setVertexJSONObject(element, new JSONObject());
				vertex.put("_id", getElementId(element));
				vertex.put("_type", "vertex");
				vertex.put("vertexType", element.getName());
				traverseSTIXElements(element, vertex, edges);
				vertices.put(vertex);
			}
				
		}
	
		String rootVertexId = rootVertex.getString("_id");
		for (int i = 0; i < vertices.length(); i++) {
			JSONObject object = vertices.getJSONObject(i);
			String id = object.getString("_id");
			JSONObject edge = setEdge(rootVertexId, "STIX_Package", id, object.getString("vertexType"));
			edges.put(edge);
		}
		vertices.put(rootVertex);

		stixGraphson.put("mode", "NORMAL");
		stixGraphson.put("vertices", vertices);
		stixGraphson.put("edges", edges);		
	
		return stixGraphson;
	}


	/**
	 * Traverses element, turns it to vertex and adding necessery edges for all the idrefs found
	 * @param element that should be traversed
	 * @param vertex JSONObject that should be added with element's children
	 * @param edges JSONArray of edges of the element (dynamically added while traversing children of this element)
	 * @return vertex vertex
	*/
	private JSONObject traverseSTIXElements(Element element, JSONObject vertex, JSONArray edges) {
		List<Element> childrenList = element.getChildren();
		for (Element child : childrenList) {
			if (child.getAttribute("idref") != null) {
				String childName = child.getName();
				
				// if referenced element is one of the main stix elements (observable, etc..) then create edge
				// else find id of outElement's(child) first main top element and inElement's(the one that is referenced) first main top element, 
				// and then create an edge between them
				if (stixElementMap.containsKey(childName)) {
					JSONObject edge = setEdge(vertex.getString("_id"), vertex.getString("vertexType"),
						child.getAttributeValue("idref"), child.getName());
					edges.put(edge);
				} else {
					String inId = null;
					String idref = child.getAttributeValue("idref");
					XPathFactory xpfac = XPathFactory.instance();
		                        XPathExpression xp = xpfac.compile("//*[@id='" + idref + "']");
					Element inElement = (Element) xp.evaluateFirst(stixDocument);
					
					do {
						if (parentElementMap.containsKey(inElement.getName())) {
							inId = inElement.getAttributeValue("id");
							break;
						}
					} while ((inElement = inElement.getParentElement()) != null);
					
					if (inId != null) {
						JSONObject edge = setEdge(vertex.getString("_id"), vertex.getString("vertexType"), inId, inElement.getName());
						edges.put(edge);	
					} else {
						logger.warn("Could not locate top element for " + child.getName() + " to construct an edge");
					
					}
				}
			}
			setVertexJSONObject(child, vertex);
			traverseSTIXElements(child, vertex, edges);
		}

		return vertex;
	}

	/**
	 * Finds element's path, converts it to graphson key, and adds content, namespace, and attributes to it
	 * @param element new Element that should be converted to graphson
	 * @param vertex vertex to be edited with element content
	 * @return vertex modified vertex  
	*/
	private JSONObject setVertexJSONObject(Element element, JSONObject vertex) {
		String path = XPathHelper.getAbsolutePath(element);
		String[] pathArray = path.split("'");
		String tag = "";
		for (int i = 1; i < pathArray.length; i = i + 4) {
			tag = tag + "--" + pathArray[i];
		}

		Namespace ns = element.getNamespace();
		vertex.put(count++ + tag + "--ns", new JSONObject().put(ns.getPrefix(), ns.getURI()));
						
		if (element.hasAttributes()) {
			vertex.put(count++ + tag + "--attr", getAttrJSONArray(element));
		}
		
		String content = element.getTextNormalize();
		if (!content.isEmpty()) {				
			vertex.put(count++ + tag + "--content", content);
		} 

		return vertex;
	}
	
	/** Creates edge between two vertices
	 * @param outId id of outVertex
	 * @param outVType type of outVertex
	 * @param inId id of inVertex
	 * @param inVtype type of inVertex
	 * @return edge between outVertex and inVertex
	 */ 
	JSONObject setEdge(String outId, String outVType, String inId, String inVType) {
		JSONObject edge = new JSONObject();
		edge.put("_id", outId + "_" + inId);
		edge.put("_type", "edge");
		edge.put("_outV", outId);
		edge.put("_inV", inId);
		edge.put("outVType", outVType);
		edge.put("inVType", inVType);
			
		return edge;
	}
	
	/**
	 * Finds id attribute of element. If element does not have id, then it creates and assigns one to it
	 * @param element whose id should be returned
	 * @return id element's id	
	*/
	private String getElementId(Element element) {
		return (element.getAttribute("id") == null) ? element.getName() + "-" + UUID.randomUUID().toString() : element.getAttributeValue("id");
	}
	
	/** 
	 * Collects element's attributes and turns them to JSONArray of attributes
	 * @param element element whose attributes should be collected
	 * @return attrArray JSONOArray of element's attributes
	*/
	private JSONArray getAttrJSONArray(Element element) {
		JSONArray attrArray = new JSONArray();
		List<Attribute> attributeList = element.getAttributes();
		for (Attribute attr : attributeList) {
			JSONObject attrObject = new JSONObject();
			Namespace attrNs = attr.getNamespace();
			if (!attrNs.getPrefix().isEmpty()) {
				attrObject.put("ns", new JSONObject().put(attrNs.getPrefix(), attrNs.getURI()));
			}
			attrObject.put("content", attr.getValue());
			attrArray.put(new JSONObject().put(attr.getName(), attrObject));
		}								

		return attrArray;
	}

	/**
	 * Validates STIXPackage according to xsd
	 * @param stixPackage that should be validated
	 * @return boolean value of validity of document
	 */
	static boolean validate(STIXPackage stixPackage) {
		try     {
                         return stixPackage.validate();
      		}
     		catch (SAXException e)  {
  		         e.printStackTrace();
       		}
   		return false;
 	}
}

