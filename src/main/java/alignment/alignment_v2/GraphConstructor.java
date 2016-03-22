package alignment.alignment_v2;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern; 

import org.json.JSONObject;
import org.json.JSONArray;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;
import org.jdom2.xpath.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GraphConstructor {
		
	private Logger logger = null;
	private ConfigFileLoader config = null;

	private static String[] stuccoVertTypeArray = {"Account", "Address", "AddressRange", "AS", "DNSName", "DNSRecord", "Exploit", "Flow", 
			"Host", "HTTPRequest", "IP", "Malware", "Organization", "Port", "Service", "Software", "Vulnerability"};
	private static String[] stixVertTypeArray = {"Campaign", "Course_Of_Action", "Exploit_Target", "Incident", "Indicator", "Observable", 
			"Threat_Actor", "TTP"};
	private Map<String, Element> stixElements = null;
	/* vertices are stored as a key/value, or id/vertex, 
	   because search jsonObject is faster and easier, than xml */
	private JSONObject graph = null;
	private JSONObject vertices = null;
	private JSONArray edges = null;

	public GraphConstructor() {
		logger = LoggerFactory.getLogger(GraphConstructor.class);
		config = new ConfigFileLoader();
	}

	public JSONObject constructGraph(Map<String, Element> stixElements) {
		this.stixElements = stixElements;
		graph = new JSONObject();
		vertices = new JSONObject();
		edges = new JSONArray();
		constructGraph();

		return graph;
	}
	
	private void constructGraph() {	
		/* turning elements into vertices first, so if any of them are not valid or 
		   do not contain required fields we would not create edges for those vertices */
		for (String id : stixElements.keySet()) {
			if (vertices.has(id)) {
				continue;
			}
			Element element = stixElements.get(id);
			JSONObject newVertex = null;
			String vertexType = null;
			/* if element is of stucco type (IP, Port, then convert it to vertex using ontology rules */
			if ((vertexType = determineVertexType(element, stuccoVertTypeArray)) != null) {
				newVertex = constructStuccoVertex(element, vertexType);
				//TODO: think some more about required fields ... some verts would be invalid, and we can luse important connections
				if (!newVertex.has("name")) {
					newVertex.put("name", element.getAttributeValue("id"));
				}
				vertices.put(element.getAttributeValue("id"), newVertex);
			/* if element is of stix type (Indicator, Incident, etc.) then convert it to vertex using default rules */
			} else if ((vertexType = determineVertexType(element, stixVertTypeArray)) != null) {
				newVertex = constructStixVertex(element, vertexType);
				vertices.put(element.getAttributeValue("id"), newVertex);
			} else {
				logger.info("Unckown type!" + new XMLOutputter().outputString(element));
			}
		}	
			
		/* now working on edges; looking for all referenced elements */	
		XPathFactory xpfac = XPathFactory.instance();
		String path = ".//*[@object_reference or @idref]";
		XPathExpression xp = xpfac.compile(path);
		for (String id : stixElements.keySet()) {
			Element outElement = stixElements.get(id);
			String outVId = outElement.getAttributeValue("id");
			/* if out vertex with this id was not valid and not created, so we do not need to construct an edge for it */
			if (!vertices.has(outVId)) {
				continue;
			}		
			/* searching outElement for referencies */
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
				/* if relation found (element with tag "Relation" some times provides it), then use it to contruct an edge;
				   some times in stix relation can be provided in children elements, sometimes in siblings, so searching them all */
				if ((relationship = ref.getChildTextNormalize("Relationship", ref.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
						continue;
					}
				}
				if ((relationship = ref.getParentElement().getChildTextNormalize("Relationship", ref.getNamespace())) != null) {
					JSONObject newEdge = constructNewEdge(outVId, inVId, relationship);
					if (verifyEdge(outVId, inVId, newEdge)) {
						edges.put(newEdge);
						continue;
					}
				} 
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
		
		/* changing json key to match vertex name; it is simpler to align it then */
	//	substituteIdForName();
		if (vertices.length() != 0) {
			graph.put("vertices", vertices);
		}

		if (edges.length() != 0) {
			graph.put("edges", edges);
		}
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

	/* function to find properties context based on provided paths in stucco_ontology.json 
	   and add found properties to new json vertex */
	private JSONObject constructStuccoVertex(Element element, String vertexType) {
		JSONObject newVertex = new JSONObject();
		JSONObject properties = config.getVertexOntology(vertexType).getJSONObject("properties");
		for (Object property : properties.keySet()) {
			String propertyName = property.toString();
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

		JSONObject observableTypeInfo = getObservableTypeInfo(element);
		if (observableTypeInfo != null) {
			newVertex.put("observableType", observableTypeInfo.getString("typeName"));
		}
		newVertex.put("sourceDocument", new XMLOutputter().outputString(element));
		newVertex.put("vertexType", vertexType);

		/* cleaning pattern that left after composing software name with missing cpe components */
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
		//	System.out.println("Pattern = "+ pattern);
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
					if (propertyValue == null) {
						return null;
					}
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

		if (propertyValue == null) {
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

	/* if during construction of vertex, required element value is not present, but referenced, then 
	   we are getting referenced element and recursively looking for a desired value */
	private String getReferencedElementName(String idref) {
		if (vertices.has(idref)) {
			JSONObject referencedVertex = vertices.getJSONObject(idref);
			return referencedVertex.getString("name");
		} else {
			if (stixElements.containsKey(idref)) {
				Element referencedElement = stixElements.get(idref);
				String referencedVertexType = determineVertexType(referencedElement, stuccoVertTypeArray);
				if (referencedVertexType != null) {
					JSONObject referencedVertex = constructStuccoVertex(referencedElement, referencedVertexType);
			//		if (verifyStuccoVertex(referencedVertex)) {
						vertices.put(idref, referencedVertex);
						return referencedVertex.getString("name");
			//		} 
				} else {
					logger.info("Could not find vertexType!");
				}
			}
		}
		return null;
	}

	/* making stix vertex (Course_Of_Action, Indicator, etc.) */
	private JSONObject constructStixVertex(Element element, String vertexType) {
		JSONObject vertex = new JSONObject();
		vertex.put("vertexType", vertexType);
		JSONObject observableTypeInfo = getObservableTypeInfo(element);
		if (observableTypeInfo != null) {
			vertex.put("observableType", observableTypeInfo.getString("typeName"));
			vertex.put("name", getObservableName(element, observableTypeInfo));
		} else {
			vertex.put("name", element.getAttributeValue("id"));
		}
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

	private JSONObject getObservableTypeInfo(Element element) {
		String name = element.getName();
		if (!name.equals("Observable")) {
			return null;
		}
		Element object = element.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		if (object == null) {
			Element observableComposition = element.getChild("Observable_Composition", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			if (observableComposition != null) {
				return config.getObservableType("ObservableComposition");
			} 
			Element event = element.getChild("Event", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			if (event != null) {
				return config.getObservableType("Event");
			}
			
			return null;
		}
		Element properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
		if (properties == null) {
			return null;
		}
		String type = properties.getAttributeValue("type", Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")).split(":")[1];
		if (type != null) {
			return config.getObservableType(type);
		}
		return null;
	}

	private String getObservableName(Element element, JSONObject observableTypeInfo) {
		String namePath = observableTypeInfo.optString("namePath");
		if (namePath == null || namePath.isEmpty()) {
			return element.getAttributeValue("id");
		} else {
			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile(namePath);
			Element foundElement = (Element) xp.evaluateFirst(element);
			if (foundElement == null) {
				return element.getAttributeValue("id");
			} else {
				String name = foundElement.getTextNormalize();
				if (name == null || name.isEmpty()) {
					return element.getAttributeValue("id");
				} else {
					return name;
				}
			}
		}
	}

	/* finds a relationship based on provided, if relationship is not provided, 
	   it is looking for the path of referenced element to try to determine it based on rules from stucc_ontology;
	   if related path is not found, then looking in graph_config */
	private String getRelationship(Element refElement, String outVId, String inVId) {
		String outVertType = vertices.getJSONObject(outVId).getString("vertexType");
		String inVertType = vertices.getJSONObject(inVId).getString("vertexType");
		String refPath = refElement.getQualifiedName();
		while (refElement.getParentElement() != null) {
			refElement = refElement.getParentElement();
			refPath = refElement.getQualifiedName() + "/" + refPath;
		}
		/* first, we are looking if refPath matches any of stucco adges, such as IP -> Contained_Within -> AddressRange, etc. */
		JSONObject outVertConfig = config.getGraphConfig().getJSONObject(outVertType);
		if (outVertConfig.has("stuccoEdges")) {
			JSONObject edges = outVertConfig.getJSONObject("stuccoEdges");
			String relationship = getRelationshipHelper(edges, refPath, refElement.getName(), inVertType);
			if (relationship != null) {
				return relationship;
			}
		}
		/* if none of stuccoEdges matches, then we need to determine a proper stixEdges, line Indicator -> SuggestedCOA -> Course_Of_Action */
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
			JSONArray inVTypeArray = edgeConfig.getJSONArray("inVType");
			for (int i = 0; i < inVTypeArray.length(); i++) {
				String inVType = inVTypeArray.getString(i);
				if (inVType.equals(inVertType)) {
					return relation.toString();
				}
			}
		}

		return null;
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

	private JSONObject constructNewEdge(String outVId, String inVId, String relationship) {
		JSONObject newEdge = new JSONObject();
		newEdge.put("inVertID", vertices.getJSONObject(inVId).getString("name"));
		newEdge.put("outVertID", vertices.getJSONObject(outVId).getString("name"));
		newEdge.put("relation", relationship);

		return newEdge;
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

	/* validating new edge between stucco elements based on stucco_ontology */
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
