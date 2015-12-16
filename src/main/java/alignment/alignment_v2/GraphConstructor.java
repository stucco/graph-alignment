package alignment.alignment_v2;

import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

import org.jdom2.output.XMLOutputter;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.AttributeType;
import org.jdom2.Content;
import org.jdom2.xpath.*;

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.stix.indicator_2.Indicator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GraphConstructor extends PreprocessSTIXwithJDOM2 {
		
	private String STIX_ONTOLOGY = "resources/ontology/stix_ontology.json";
	private String VERTEX_TYPE_CONFIG = "resources/ontology/vertex_type_config.json";

	private Document stixDoc = null;

	/* vertices are stored as a key/value, or id/vertex, 
	   because search jsonObject is faster and easier, than xml */
	private JSONObject ontology = null;
	private JSONObject vertexTypeConfig = null;
	private JSONObject graph = null;
	private JSONObject vertices = null;
	private JSONArray edges = null;

	private Logger logger;

	public GraphConstructor() {
		logger = LoggerFactory.getLogger(GraphConstructor.class);
		graph = new JSONObject();
		vertices = new JSONObject();
		edges = new JSONArray();
		
		try {
			/* required to map new incomming stix xml to vertesType (like is it IP, Port, etc ?) */
			vertexTypeConfig = new JSONObject(new String(Files.readAllBytes(Paths.get(VERTEX_TYPE_CONFIG))));
			/* required to construct a graph, to do all the comparisons, and stix xml editing */
			ontology = new JSONObject(new String(Files.readAllBytes(Paths.get(STIX_ONTOLOGY))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public JSONObject getGraph() {
		return graph;
	}

	/* function to take stix xml as a string, 
	   normalize it (split into main components: Observable, TTP, etc.), 
	   and pass it to farther conversion to vertex */
	public void constructGraph(String stix) {
	//	STIXPackage stixPack = new STIXPackage().fromXMLString(stix);
	//	System.out.println(stixPack.getObservables().getObservables());
	//	List<Observable> observableList = (stixPack.getObservables() != null) ? stixPack.getObservables().getObservables() : null;
	//	List indicatorList = (stixPack.getIndicators() != null) ? stixPack.getIndicators().getIndicators() : null;
	//	System.out.println(indicatorList.size());

		normalizeSTIXPackage(stix);
		stixDoc = getSTIXDocument();
		constructGraphFromDocument(stixDoc);
	}
	
	/* takes normalized stix xml as a Document, using xpath to find elements and then tern them into vertices */
	private void constructGraphFromDocument(Document stixDoc) {	
		String path = null;
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = null;
		
		/* selecting all the main elements to turn them into vertices */
		path = 
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Exploit_Targets']/*[local-name() = 'Exploit_Target'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'TTPs']/*[local-name() = 'TTP'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Observables']/*[local-name() = 'Observable'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Indicators']/*[local-name() = 'Indicator'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Incidents']/*[local-name() = 'Incident'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Courses_Of_Action']/*[local-name() = 'Course_Of_Action'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Campaigns']/*[local-name() = 'Campaign'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Threat_Actors']/*[local-name() = 'Threat_Actor']";
			
		xp = xpfac.compile(path);
		List<Element> elementList = (List<Element>) xp.evaluate(stixDoc);
		/* turning elements into vertices first, so if any of them are not valid or do not contain required fields we would not create edges for those vertices */
		for (Element element : elementList) {
			JSONObject newVertex = turnElementIntoVertex(element);
			if (testRequiredFields(newVertex)) {
				vertices.put(element.getAttributeValue("id"), newVertex);
			}
		}	
			
		if (vertices.length() != 0) {
			graph.put("vertices", vertices);
		}
		/* now working on edges */	
		path = ".//*[@object_reference or @idref]";
		xp = xpfac.compile(path);
		for (Element element : elementList) {
			String outVId = element.getAttributeValue("id");
			/* if vertex with this id was not valid and not created, so we do not need to construct an edge for it */
			if (!vertices.has(outVId)) {
				continue;
			}		
			List<Element> inVList = (List<Element>) xp.evaluate(element);
			for (Element inV : inVList) {			
				String inVId = null;
				if ((inVId = inV.getAttributeValue("idref")) == null) {
					inVId = inV.getAttributeValue("object_reference");
				}
					
				/* again, if referenced element was invalid and not created, we do not need this edge */
				if (!vertices.has(inVId)) {
					continue;
				} 
				String relationship = null;
				if ((relationship = inV.getParentElement().getChildTextNormalize("Relationship", inV.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
					}
				} else if ((relationship = inV.getChildTextNormalize("Relationship", inV.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
					}
				} else {
					System.out.println("No relationship ... need to come up with something");
						relationship = determineRelationship(outVId, inV);
						if (relationship != null) {
							JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
							if (verifyEdge(outVId, inVId, newEdge)) {
								edges.put(newEdge);
							} else {
								logger.info("[WARNING] Found new relationship!!! Need to edit stix_ontology.json.");
							}												
						} else {													
							logger.info("[WARNING] Found new relationship!!! Need to investigate and add to graph_type_config.json.");
						}
				}
			}
		}
		if (edges.length() != 0) {
			graph.put("edges", edges);
		}
	}

	private JSONObject turnElementIntoVertex(Element element) {
		printElement(element);
		String vertexType = determineVertexType(element);
		logger.info(vertexType);
		if (vertexType == null) {
			vertexType = applyDefaultXPath(element);
		} 
		if (vertexType == null) {
			return null;
		}

		return constructNewVertex(element, vertexType);
	}

	private String applyDefaultXPath(Element element) {
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(".[local-name() = 'Observable']/*[local-name() = 'Object']/*[local-name() = 'Properties']/@*[local-name()='type']");
		Element foundElement = (Element) xp.evaluateFirst(element);
		
		return (foundElement == null) ? null : foundElement.getTextNormalize();
	}

	/* function to traverse vertex_type_config.json stored into vertexTypeConfig
	   to determine what is a vertexType of this stix element */
	private String determineVertexType(Element element) {
		for (Object keyObject : vertexTypeConfig.keySet()) {
			String key = keyObject.toString();
			JSONObject possibleType = vertexTypeConfig.getJSONObject(key);
			if (possibleType.has("path")) {
				if (findIfPathExists(element, possibleType.getString("path"))) {
					return key;
				}
			} else if (possibleType.has("regex")) {
				if (findIfRegexMatches(element, possibleType.getJSONObject("regex"))) {
					return key;
				}
			}
		}
		return null;
	}

	/* looking for a specific path in the element that determines it's vertexType */
	private boolean findIfPathExists(Element element, String path) {
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(path);
		Element foundElement = (Element) xp.evaluateFirst(element);

		return (foundElement == null) ? false : true;
	}

	/* founction to find vertexType based on the existence of required xml element 
	   and its value matching a provided regex */
	private boolean findIfRegexMatches(Element element, JSONObject json) {
		String path = json.getString("path");
		String pattern = json.getString("pattern");
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(path);
		Element foundElement = (Element) xp.evaluateFirst(element);
		
		return (foundElement == null) ? false : foundElement.getTextNormalize().matches(pattern);
	}	
	
	/* founction to find properties's context based on provided paths in stix_ontology.json and 
	   add found properties to new json vertex */
	private JSONObject constructNewVertex(Element element, String vertexType) {
		JSONObject newVertex = new JSONObject();
		String name = null;
		JSONObject vertOntology = ontology.getJSONObject("definitions").getJSONObject(vertexType);
		JSONObject properties = vertOntology.getJSONObject("properties");
		for (Object nameObject : properties.keySet()) {
			String nameString = nameObject.toString();
			JSONObject propertyInfo = properties.getJSONObject(nameString);
			if (propertyInfo.has("xpath")) {
				Object content = getElementContent(element, propertyInfo);
				newVertex.put(nameString, content);
			}
		}

		newVertex.put("sourceDocument", new XMLOutputter().outputString(element));
		newVertex.put("vertexType", vertexType);

		/* cleaning pattern that left after composing software name and missing cpe some components */
		if (vertexType.equals("Software")) {
			newVertex.put("name", cleanCpeName(newVertex.getString("name")));
		}
		return newVertex;
	}

	/* function helper: finds element's content based on provided xpath;
	   used in construction of properties of new json vertex */
	private Object getElementContent(Element element, JSONObject propertyInfo) {
		String pattern = null;
		if (propertyInfo.has("pattern")) {
			pattern = propertyInfo.getString("pattern");
		} 
		String xpath = propertyInfo.getString("xpath");
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(xpath);
		if (propertyInfo.get("cardinality").equals("single")) {
			/* checking for cardinality and no pattern (content will be not a combination of contents from different elements),
			   then limit xpath search to first found element, so it will not continue looking */
			if (pattern == null) { 
				Element foundElement = (Element) xp.evaluateFirst(element);
				return (foundElement == null) ? null : processElementContent(foundElement, propertyInfo);
			} else {
				List<Element> foundElementList = (List<Element>) xp.evaluate(element);
				if (foundElementList == null) {
					return null;

				}
				/* this case is for composite propertyValue with pattern; like cpe with part, vendor, product, etc
				   which require content of a set of elements arranged according a pattern */
				String propertyValue = null;
				for (Element foundElement : foundElementList) {
					propertyValue = processElementContent(foundElement, propertyInfo);
					if (pattern != null) {
						pattern = pattern.replace(foundElement.getName(), propertyValue);
					}
				}
				return (pattern == null) ? propertyValue : pattern;
			}
		} else { /* this is a case when cardinality = set */
			/* testing for cardinality = set, and returning a set of resulting values */
			List<Element> foundElementList = (List<Element>) xp.evaluate(element);
			if (foundElementList == null) {
				return null;
			}
			if (pattern == null) {
				Set<String> set = new HashSet<String>();
				for (Element foundElement : foundElementList) {
					set.add(processElementContent(foundElement, propertyInfo));
				}
				return set;
			} else {
				//TODO double check on propertyValue with pattern and cardinality = set ...
				// not sure how to handle those yet, but it should not happen ... here is a check for it
				logger.info("[WARNING] More than one value was found with pattern and set cardinality!!!");
				return null;
			}		
		}
	}

	private String processElementContent(Element foundElement, JSONObject propertyInfo) {
		String propertyValue = null;
		if (foundElement.getAttribute("idref") != null) {
			String idref = foundElement.getAttributeValue("idref");
			propertyValue = getReferencedElementName(idref);
		} else if (foundElement.getAttribute("object_reference") != null) {
			String object_reference = foundElement.getAttributeValue("object_reference");
			propertyValue = getReferencedElementName(object_reference);
		} else {
			propertyValue = foundElement.getTextNormalize();
		}
			//TODO decide later on what to do with delimiters ....
		//	if (foundElement.hasAttribute("delimiter")) {
		//		String delimiter = foundElement.getAttributeValue("delimiter");
		//		Split[] propertyValueList = propertyValue.split(delimiter);
		//	}

		if (propertyValue.isEmpty()) {
			return null;
		}
		if (propertyInfo.has("regex")) {
			String regexPattern = propertyInfo.getString("regex");
			Pattern p = Pattern.compile(regexPattern);
			Matcher m = p.matcher(propertyValue);
			if (m.find()) {
				propertyValue = m.group(1);
			}
		}
		if (propertyInfo.has("applyFunction")) {
			if (propertyInfo.getString("applyFunction").equals("ipToLong")) {
				long ipInt = ipToLong(propertyValue); 
				propertyValue = String.valueOf(ipInt); 
			}
		}
		return propertyValue;
	}

	/* helper function: turns ip string to long; required as a property for ip and addressRange vertices */
	private long ipToLong(String ipString)	{
		long ipLong = 0;
		long ip;
		String[] ipArray = ipString.split("\\.");
		for (int i = 3; i >= 0; i--) {
			ip = Long.parseLong(ipArray[3 - i]);
			ipLong |= ip << (i * 8);
		}
		
		return ipLong;
	}

	private String cleanCpeName(String propertyValue) {
		String[] cpe = "Property:Vendor:Product:Version:Update:Edition:Language".split(":");
		for (String cpeComponent : cpe) {
			propertyValue = propertyValue.replace(cpeComponent, "");
		}

		return propertyValue;
	}

	private String getReferencedElementName(String idref) {
		if (vertices.has(idref)) {
			JSONObject referencedVertex = vertices.getJSONObject(idref);

			return referencedVertex.getString("name");
		} else {
			String xpath = "//*[@id = '" + idref + "']";
			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile(xpath);
			Element referencedElement = (Element) xp.evaluateFirst(stixDoc);
			printElement(referencedElement);
			JSONObject referencedVertex = turnElementIntoVertex(referencedElement);
			vertices.put(idref, referencedVertex);

			return referencedVertex.getString("name");
		}
	}
	
	/* tests newVertex to insure all the required fields were found and added */	
	private boolean testRequiredFields(JSONObject newVertex) {
		if (newVertex == null) {
			logger.info("[WARNING] newVertex equals null");
			return false;
		}
		String vertexType = newVertex.getString("vertexType");
		JSONArray requiredFields = ontology.getJSONObject("definitions").getJSONObject(vertexType).getJSONArray("required");
		for (int i = 0; i < requiredFields.length(); i++) {
			String requiredField = requiredFields.getString(i);
			if (!newVertex.has(requiredField)) {
				logger.info("[WARNING] newVertex is missing a required field: " + requiredField);
				return false;
			}
		}

		return true;
	}

	/* finds a relationship based on provided, if relationship is not provided, 
	   it isloocking for the path of referenced element to try to determine it based on rules from VERTEX_TYPE_CONFIG */
	private String determineRelationship(String outVId, Element refElement) {
		String refPath = refElement.getQualifiedName();
		while (refElement.getParentElement() != null) {
			refElement = refElement.getParentElement();
			refPath = refElement.getQualifiedName() + "/" + refPath;
		}
		System.out.println("reference element path = " + refPath);
		String vertexType = vertices.getJSONObject(outVId).getString("vertexType");
		if (vertexTypeConfig.getJSONObject(vertexType).has("edges")) {	
			JSONObject edges = vertexTypeConfig.getJSONObject(vertexType).getJSONObject("edges");
			for (Object key : edges.keySet()) {						
				String idrefPath = edges.getJSONObject(key.toString()).getString("path");
				if (idrefPath.equals(refPath)) {
					return key.toString();
				}
			}
		}

		return null;
	}

	private JSONObject constructNewEdge(String outVId, String inVId, String relationship) {
		JSONObject newEdge = new JSONObject();
		newEdge.put("inV", vertices.getJSONObject(inVId).getString("name"));
		newEdge.put("outV", vertices.getJSONObject(outVId).getString("name"));
		newEdge.put("label", relationship);

		return newEdge;
	}	

	/* function to verify that connected vertices are of correct types, or it will throw a warning ... will need to investigate later */
	private boolean verifyEdge(String outVId, String inVId, JSONObject newEdge) {
		String outVType = vertices.getJSONObject(outVId).getString("vertexType");
		String inVType = vertices.getJSONObject(inVId).getString("vertexType");
		JSONObject edgeOntology = ontology.getJSONObject("definitions").getJSONObject(newEdge.getString("label"));
		JSONObject properties = edgeOntology.getJSONObject("properties");
		JSONArray propertyEnum = properties.getJSONObject("outVType").getJSONArray("enum");
		boolean wrongOutVType = true;
		for (int i = 0; i < propertyEnum.length(); i++) {
			String propertyValue = propertyEnum.getString(i);
			if (propertyValue.equals(outVType)) {
				wrongOutVType = false;
				break;
			}
		} 
		if (wrongOutVType) {
			logger.info("[WARNING] outVType does not match ontology requirements!!!");
			logger.info("[WARNING] Required one of: ");
			for (int i = 0; i < propertyEnum.length(); i++) {
				logger.info("[WARNING]		" + propertyEnum.getString(i));
			}
			logger.info("[WARNING] But was found : " + outVType);
		}
		boolean wrongInVType = true;
		propertyEnum = properties.getJSONObject("inVType").getJSONArray("enum");
		for (int i = 0; i < propertyEnum.length(); i++) {
			String propertyValue = propertyEnum.getString(i);
			if (propertyValue.equals(inVType)) {
				wrongInVType = false;
				break;
			}
		} 
		if (wrongInVType) {
			logger.info("[WARNING] inVType does not match ontology requirements!!!");
			logger.info("[WARNING] Required one of: ");
			for (int i = 0; i < propertyEnum.length(); i++) {
				logger.info("[WARNING]		" + propertyEnum.getString(i));
			}
			logger.info("[WARNING] But was found : " + inVType);
		}

		return (wrongOutVType | wrongInVType) ? false : true;
	}
}
