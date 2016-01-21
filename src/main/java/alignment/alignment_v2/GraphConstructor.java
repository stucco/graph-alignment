package alignment.alignment_v2;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.io.IOException;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GraphConstructor extends PreprocessSTIXwithJDOM2 {
		
	/* xpath to select all the main elements to turn them into vertices */
	private static String path = 
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Exploit_Targets']/*[local-name() = 'Exploit_Target'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'TTPs']/*[local-name() = 'TTP'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Observables']/*[local-name() = 'Observable'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Indicators']/*[local-name() = 'Indicator'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Incidents']/*[local-name() = 'Incident'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Courses_Of_Action']/*[local-name() = 'Course_Of_Action'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Campaigns']/*[local-name() = 'Campaign'] | " +
			"/*[local-name() = 'STIX_Package']/*[local-name() = 'Threat_Actors']/*[local-name() = 'Threat_Actor']";
	private static String[] stuccoVertTypeArray = {"Account", "Address", "AddressRange", "AS", "DNSName", "DNSRecord", "Exploit", "Flow", 
			"Host", "HTTPRequest", "IP", "Malware", "Organization", "Port", "Service", "Software", "Vulnerability"};
	private static String[] stixVertTypeArray = {"Campaign", "Course_Of_Action", "Exploit_Target", "Incident", "Indicator", "Observable", 
			"Threat_Actor", "TTP"};
	private Document stixDoc = null;
	/* vertices are stored as a key/value, or id/vertex, 
	   because search jsonObject is faster and easier, than xml */
	private JSONObject graph = null;
	private JSONObject vertices = null;
	private JSONArray edges = null;
	
	private Logger logger = null;
	private ConfigFileLoader config = null;

	public GraphConstructor() {
		logger = LoggerFactory.getLogger(GraphConstructor.class);
		config = new ConfigFileLoader();
		graph = new JSONObject();
		vertices = new JSONObject();
		edges = new JSONArray();
	}

	public JSONObject getGraph() {
		return graph;
	}

	/* function to take stix xml as a string, 
	   normalize it (split into main components: Observable, TTP, etc.), 
	   and pass it to farther conversion to vertex */
	public void constructGraph(String stix) {
		normalizeSTIXPackage(stix);
		stixDoc = getSTIXDocument();
		constructGraphFromDocument(stixDoc);
	}
	
	/* takes normalized stix xml as a Document, using xpath to find elements and then tern them into vertices */
	private void constructGraphFromDocument(Document stixDoc) {	
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = null;
		xp = xpfac.compile(path);
		List<Element> elementList = setElementList(stixDoc);
		/* turning elements into vertices first, so if any of them are not valid or 
		   do not contain required fields we would not create edges for those vertices */
		for (Element element : elementList) {
			if (vertices.has(element.getAttributeValue("id"))) {
				continue;
			}
			JSONObject newVertex = null;
			String vertexType = null;
			/* if element is of stucco type (IP, Port, then convert it to vertex using ontology rules */
			if ((vertexType = determineVertexType(element, stuccoVertTypeArray)) != null) {
				newVertex = constructStuccoVertex(element, vertexType);
				if (verifyStuccoVertex(newVertex)) {
					vertices.put(element.getAttributeValue("id"), newVertex);
				}
			/* if element is of stix type (Indicator, Incident, etc.) then convert it to vertex using default rules */
			} else if ((vertexType = determineVertexType(element, stixVertTypeArray)) != null) {
				newVertex = constructStixVertex(element, vertexType);
				vertices.put(element.getAttributeValue("id"), newVertex);
			} 
		}	
			
		/* now working on edges; looking for all referenced elements */	
		path = ".//*[@object_reference or @idref]";
		xp = xpfac.compile(path);
		for (Element outElement : elementList) {
			String outVId = outElement.getAttributeValue("id");
			/* if out vertex with this id was not valid and not created, so we do not need to construct an edge for it */
			if (!vertices.has(outVId)) {
				continue;
			}		
			List<Element> refList = (List<Element>) xp.evaluate(outElement);
			for (Element ref : refList) {			
				String inVId = null;
				if ((inVId = ref.getAttributeValue("idref")) == null) {
					inVId = ref.getAttributeValue("object_reference");
				}
					
				/* again, if in vertex (referenced element) was invalid and not created, we do not need this edge */
				if (!vertices.has(inVId)) {
					continue;
				} 
				/* searching for relation in provided xml */
				String relationship = null;
				/* if relation found, then use it to contruct an edge */
				if ((relationship = ref.getChildTextNormalize("Relationship", ref.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
					}
				} else if ((relationship = ref.getParentElement().getChildTextNormalize("Relationship", ref.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
					}
				} else {
					/* if relation is not provided use graph_config to determine it, and then construct a new edge */
					relationship = getRelationship(ref, outVId, inVId);
					if (relationship != null) {
						JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
						edges.put(newEdge);
					} else {													
						logger.info("Could not determine relaiton berteen vertices:");
						logger.info("		outVertType = " + vertices.getJSONObject(outVId).getString("vertexType"));
						logger.info("		inVertType = " + vertices.getJSONObject(inVId).getString("vertexType"));
					}
				}
			}
		}
		
		/* changing json key to match vertex name; it is simpler to align it then */
		substituteIdForName();
		if (vertices.length() != 0) {
			graph.put("vertices", vertices);
		}

		if (edges.length() != 0) {
			graph.put("edges", edges);
		}
	}

	/* making a set of main stix xml elements to differ them from stucco xml elements, 
           since they are converted to vertices in a different way */
	private List<Element> setElementList(Document stixDoc) {
		Set<String> stixSet = new HashSet<String>();
		stixSet.add("Observables");
		stixSet.add("Indicators");
		stixSet.add("TTPs");
		stixSet.add("Exploit_Targets");
		stixSet.add("Incidents");
		stixSet.add("Courses_Of_Action");
		stixSet.add("Campaigns");
		stixSet.add("Threat_Actors");
		List<Element> stixElementList = new ArrayList<Element>();
		Element rootElement = stixDoc.getRootElement();
		List<Element> children = rootElement.getChildren();
		for (Element child : children) {
			if (stixSet.contains(child.getName())) {
				stixElementList.addAll(child.getChildren());	
			}
		}

		return stixElementList; 
	}

	/* function to traverse graph_config.json 
	   to determine what is a vertexType of this stix element */
	private String determineVertexType(Element element, String[] vertTypeArray) {
		JSONObject graphConfig = config.getGraphConfig();
		for (int i = 0; i < vertTypeArray.length; i++) {
			String key = vertTypeArray[i];
			JSONObject possibleType = graphConfig.getJSONObject(key);
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

	/* making stix vertex (Course_Of_Action, Indicator, etc.) */
	private JSONObject constructStixVertex(Element element, String vertexType) {
		JSONObject vertex = new JSONObject();
		vertex.put("vertexType", vertexType);
		vertex.put("name", element.getAttributeValue("id"));
		vertex.put("sourceDocument", new XMLOutputter().outputString(element));
		List<String> description = getElementDescriptionList(element);
		if (!description.isEmpty()) {
			vertex.put("description", description);
		}
		return vertex;
	}

	/* collecting all the descriptions from xml element into list for default element to vertex convertion */
	private List<String> getElementDescriptionList(Element element) {
		List<String> descriptionList = new ArrayList<String>();
		if (element.getName().equals("Description")) {
			String content = element.getTextNormalize();
			if (!content.isEmpty()) {
				descriptionList.add(content);
			}
		} else {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				descriptionList.addAll(getElementDescriptionList(child));
			}	
		}

		return descriptionList;
	}
	
	/* function to find properties context based on provided paths in stucco_ontology.json and 
	   add found properties to new json vertex */
	private JSONObject constructStuccoVertex(Element element, String vertexType) {
		JSONObject newVertex = new JSONObject();
		JSONObject stuccoOntology = config.getStuccoOntology();
		JSONObject properties = stuccoOntology.getJSONObject("definitions").getJSONObject(vertexType).getJSONObject("properties");
		for (Object key : properties.keySet()) {
			String propertyName = key.toString();
			JSONObject propertyInfo = properties.getJSONObject(propertyName);
			if (propertyInfo.has("xpath")) {
				Object content = getElementContent(element, propertyInfo);
				if (content != null) {
					newVertex.put(propertyName, content);
				}
			} else {
				if (!propertyName.equals("vertexType")) {
					logger.error("Could not find xpath for " + vertexType + ", property: " + propertyName + "!");
				}
			}
		}

		newVertex.put("sourceDocument", new XMLOutputter().outputString(element));
		newVertex.put("vertexType", vertexType);

		/* cleaning pattern that left after composing software name and with missing cpe components */
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
					pattern = (pattern == null) ? null : pattern.replace(foundElement.getName(), propertyValue);
				}
				return (pattern == null) ? propertyValue : pattern;
			}
		} else { /* this is a case when cardinality = set */
			/* testing for cardinality = set, and returning a set of resulting values */
			List<Element> foundElementList = (List<Element>) xp.evaluate(element);
			if (foundElementList.isEmpty()) {
				return null;
			}
			if (pattern == null) {
				Set<String> set = new HashSet<String>();
				for (Element foundElement : foundElementList) {
					set.add(processElementContent(foundElement, propertyInfo));
				}
				return (set.isEmpty()) ? null : set;
			} else {
				//TODO double check on propertyValue with pattern and cardinality = set ...
				// not sure how to handle those yet, but it should not happen ... here is a check for it
				logger.info("More than one value was found with pattern and set cardinality!!!");
				return null;
			}		
		}
	}

	/* turning element content into vertex properties, such as looking for description, name, etc. */
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
		/* regex required in cases like differ IP and AddressRange, where besides value everything else is the same */
		if (propertyInfo.has("regex")) {
			String regexPattern = propertyInfo.getString("regex");
			Pattern p = Pattern.compile(regexPattern);
			Matcher m = p.matcher(propertyValue);
			if (m.find()) {
				propertyValue = m.group(1);
			}
		}
		/* required in cases like convert IP to long, etc. */
		if (propertyInfo.has("applyFunction")) {
			if (propertyInfo.getString("applyFunction").equals("ipToLong")) {
				long ipInt = ipToLong(propertyValue); 
				propertyValue = String.valueOf(ipInt); 
			}
		}
		return propertyValue;
	}

	/* if during construction of vertex required element value is not present, but referenced, then 
	   getting referenced element, and recursively looking for a desired value */
	private String getReferencedElementName(String idref) {
		if (vertices.has(idref)) {
			JSONObject referencedVertex = vertices.getJSONObject(idref);
			return referencedVertex.getString("name");
		} else {
			String xpath = "//*[@id = '" + idref + "']";
			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile(xpath);
			Element referencedElement = (Element) xp.evaluateFirst(stixDoc);
			String referencedVertexType = determineVertexType(referencedElement, stuccoVertTypeArray);
			if (referencedVertexType != null) {
				JSONObject referencedVertex = constructStuccoVertex(referencedElement, referencedVertexType);
				if (verifyStuccoVertex(referencedVertex)) {
					vertices.put(idref, referencedVertex);
					return referencedVertex.getString("name");
				} 
			}
		}
		return null;
	}

	/* finds a relationship based on provided, if relationship is not provided, 
	   it is loocking for the path of referenced element to try to determine it based on rules from stucc_ontology;
	   if related path is not found, then loocking in graph_config */
	private String getRelationship(Element refElement, String outVId, String inVId) {
		String outVertType = vertices.getJSONObject(outVId).getString("vertexType");
		String inVertType = vertices.getJSONObject(inVId).getString("vertexType");
		String refPath = refElement.getQualifiedName();
		while (refElement.getParentElement() != null) {
			refElement = refElement.getParentElement();
			refPath = refElement.getQualifiedName() + "/" + refPath;
		}
		JSONObject outVertConfig = config.getGraphConfig().getJSONObject(outVertType);
		if (outVertConfig.has("stuccoEdges")) {
			JSONObject edges = outVertConfig.getJSONObject("stuccoEdges");
			String relationship = getRelationshipHelper(edges, refPath, refElement.getName(), inVertType);
			if (relationship != null) {
				return relationship;
			}
		}
		if (outVertConfig.has("stixEdges")) {
			JSONObject edges = outVertConfig.getJSONObject("stixEdges");
			String relationship = getRelationshipHelper(edges, refPath, refElement.getName(), inVertType);
			if (relationship != null) {
				return relationship;
			}
		}

		return null;
	}	
		
	private String getRelationshipHelper(JSONObject edges, String refPath, String refElementName, String inVertType) {
		for (Object relation : edges.keySet()) {
			JSONObject edgeConfig = edges.getJSONObject(relation.toString());
			if (edgeConfig.has("outElementName")) {
				if (refElementName.equals("Related_Object") || !refElementName.equals(edgeConfig.getString("outElementName"))) {
					continue;	
				}
			}
			if (edgeConfig.has("path")) {
				if (!refPath.equals(edgeConfig.getString("path"))) {
					continue;
				}
			}
			boolean contains = false;
			JSONArray inVTypeArray = edgeConfig.getJSONArray("inVType");
			for (int i = 0; i < inVTypeArray.length(); i++) {
				String inVType = inVTypeArray.getString(i);
				if (inVType.equals(inVertType)) {
					contains = true;
					return relation.toString();
				}
			}
		}

		return null;
	}

	private JSONObject constructNewEdge(String outVId, String inVId, String relationship) {
		JSONObject newEdge = new JSONObject();
		newEdge.put("inVertID", vertices.getJSONObject(inVId).getString("name"));
		newEdge.put("outVertID", vertices.getJSONObject(outVId).getString("name"));
		newEdge.put("relation", relationship);

		return newEdge;
	}	

	/* testing if elements id equals idref, or if element contains child with id equals idref;
	   required to construct an edges */
	private boolean containsIDRef(Element element, String idref) {
		String id = null;
		if ((id = element.getAttributeValue("id")) != null) {
			if (id.equals(idref)) {
				return true;
			}
		}
		List<Element> children = element.getChildren();
		for (Element child : children) {
			if (containsIDRef(child, idref)) {
				return true;
			} 
		}
		
		return false;
	}
	
	/* tests newVertex to insure all the required fields were found and added */	
	private boolean verifyStuccoVertex(JSONObject newVertex) {
		if (newVertex == null) {
			logger.info("newVertex equals null");
			return false;
		}
		String vertexType = newVertex.getString("vertexType");
		JSONObject stuccoOntology = config.getStuccoOntology();
		JSONArray requiredFields = stuccoOntology.getJSONObject("definitions").getJSONObject(vertexType).getJSONArray("required");
		for (int i = 0; i < requiredFields.length(); i++) {
			String requiredField = requiredFields.getString(i);
			if (!newVertex.has(requiredField)) {
				logger.info("newVertex is missing a required field: " + requiredField);
				return false;
			}
		}

		return true;
	}

	/* validating new edge between stucco elements based stucco_ontology */
	private boolean verifyEdge(String outVId, String inVId, JSONObject newEdge) {
		String outVType = vertices.getJSONObject(outVId).getString("vertexType");
		String inVType = vertices.getJSONObject(inVId).getString("vertexType");
		JSONObject edgeOntology = config.getStuccoOntology().getJSONObject("definitions").getJSONObject(newEdge.getString("relation"));
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
			logger.info(" - outVType does not match ontology requirements!!!");
			logger.info("   Required one of: ");
			for (int i = 0; i < propertyEnum.length(); i++) {
				logger.info("		" + propertyEnum.getString(i));
			}
			logger.info("   But found : " + outVType);
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
			logger.info(" - inVType does not match ontology requirements!!!");
			logger.info(" - Required one of: ");
			for (int i = 0; i < propertyEnum.length(); i++) {
				logger.info("		" + propertyEnum.getString(i));
			}
			logger.info("   But found : " + inVType);
		}

		return (wrongOutVType | wrongInVType) ? false : true;
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
		
	/* Using UUID as a json key to vertex is convenient while turning xml into a graph, 
           but for alignment using name as a json key for vertex is faster */
	private void substituteIdForName() {
		Map<String, String> idToNameMap = new HashMap<String, String>();
		for (Object key : vertices.keySet()) {
			String id = key.toString();
			String name = vertices.getJSONObject(id).getString("name");
			if (!id.equals(name)) {
				idToNameMap.put(id, name);
			}
		}

		for (String id : idToNameMap.keySet()) {
			JSONObject vert = vertices.getJSONObject(id);
			vertices.put(idToNameMap.get(id), vert); 
			vertices.remove(id);
		}
	}
}
