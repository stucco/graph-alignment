package gov.ornl.stucco.alignment;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern; 
import java.util.Iterator;

import org.json.JSONObject;
import org.json.JSONArray;   

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute; 
import org.jdom2.xpath.XPathFactory; 
import org.jdom2.xpath.XPathExpression; 

import org.slf4j.Logger;
import org.slf4j.LoggerFactory; 

/**
 * Converting a map of stix XML elements into JSON graph
 *
 * @author Maria Vincent
 */
 
public class GraphConstructor {
		
	private Logger logger = null;

	private static String[] vertTypeArray = {
		"IP", 
		"AddressRange", 
		"Exploit", 
		"Malware", 
		"Vulnerability", 
		"Weakness", 
		"Campaign", 
		"Course_Of_Action", 
		"Exploit_Target", 
		"Incident", 
		"Indicator", 
		"Observable", 
		"Threat_Actor", 
		"TTP"
	};	
	/* 
	 *	vertices are stored as a key/value, or id/vertex, 
	 *	because search jsonObject is faster and easier, than xml 
	 */
	private JSONObject graph = null;
	private JSONObject vertices = null;
	private JSONArray edges = null;

	private Map<String, Element> stixElements = null;

	public String print(Element e) {
		XMLOutputter xmlOutputter = new XMLOutputter(Format.getPrettyFormat());
		System.out.println(xmlOutputter.outputString(e));

		return xmlOutputter.outputString(e);
	}

	public GraphConstructor() {
		logger = LoggerFactory.getLogger(GraphConstructor.class);
	}

	public JSONObject constructGraph(Map<String, Element> stixElements) {
		if (stixElements == null) {
			return null;
		} else {
			this.stixElements = stixElements;
			graph = new JSONObject();
			vertices = new JSONObject();
			edges = new JSONArray();
			constructGraph();
		}

		return graph;
	}
	
	private void constructGraph() {	
		/* turning elements into vertices first, so if any of them are not valid or 
		   do not contain required fields we would not create edges for those vertices */
		for (Map.Entry<String, Element> entry : stixElements.entrySet()) {
			/* some vertices are created out of order; example is when required field value is in references element */
			if (vertices.has(entry.getKey())) {
				continue;
			}
			Element element = entry.getValue();
			String vertexType = determineVertexType(element); 
			JSONObject newVertex = constructVertex(element, vertexType);
			vertices.put(element.getAttributeValue("id"), newVertex);
		}	
			
		/* now working on edges; looking for all referenced elements and constructing new edges */	
		XPathFactory xpfac = XPathFactory.instance();
		String path = ".//*[@object_reference or @idref]";
		XPathExpression xp = xpfac.compile(path);
		for (Map.Entry<String, Element> entry : stixElements.entrySet()) {
			Element outElement = entry.getValue();
			String outVertID = outElement.getAttributeValue("id");
			/* if out vertex with this id was not valid and not created, so we do not need to construct an edge for it */
			if (!vertices.has(outVertID)) {
				continue;
			}		
			/* searching outElement for referencies */
			List<Element> refList = (List<Element>) xp.evaluate(outElement);
			for (Element ref : refList) {	
				String inVertID = null;
				if ((inVertID = ref.getAttributeValue("idref")) == null) {
					inVertID = ref.getAttributeValue("object_reference");
				}	
				/* again, if in vertex (referenced element) was invalid and not created, we do not need this edge */
				if (!vertices.has(inVertID)) {
					continue;
				} 
				/* searching for relation using stucco_ontology */
				String relationship = getRelationship(ref, outVertID, inVertID);
				if (relationship == null) {
					relationship = vertices.getJSONObject(outVertID).getString("vertexType") + "Related" + vertices.getJSONObject(inVertID).getString("vertexType");												
					logger.info("Could not determine relation between vertices:");
					logger.info("		outVertType = " + vertices.getJSONObject(outVertID).getString("vertexType"));
					logger.info("		inVertType = " + vertices.getJSONObject(inVertID).getString("vertexType"));
					logger.info("		-> assigned constructed relationship: " + relationship);
				}			
				JSONObject newEdge = constructNewEdge(outVertID, inVertID, relationship);
				edges.put(newEdge);	
			}
		}
		
		if (vertices.length() != 0) {
			graph.put("vertices", vertices);
		}

		if (edges.length() != 0) {
			graph.put("edges", edges);
		}
	}

	/* 
	 *	function to traverse graph_config.json 
	 *	to determine what is a vertexType of this stix element 
	 */
	private String determineVertexType(Element element) {
		for (int i = 0; i < vertTypeArray.length; i++) {
			String vertexType = vertTypeArray[i];
			JSONObject typeOntology = ConfigFileLoader.getVertexOntology(vertexType);
			if (typeOntology.has("xpath")) {
				if (findIfPathExists(element, typeOntology.getString("xpath"))) {
					return vertexType;
				}
			} else if (typeOntology.has("regex")) {
				if (findIfRegexMatches(element, typeOntology.getJSONObject("regex"))) {
					return vertexType;
				}
			} else {
				logger.info("Element " + element.getName() + " does not have xpath or regex to deternime it's vertexType!");
			}
		}
		return null;
	}

	/* 
	 *	looking for a specific path in the element that determines it's vertexType 
	 */
	private boolean findIfPathExists(Element element, String path) {
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(path);
		Element foundElement = (Element) xp.evaluateFirst(element);

		return (foundElement == null) ? false : true;
	}

	/* 
	 *	founction to find vertexType based on the existence of required xml element 
	 *	and its value matching a provided regex 
	 */
	private boolean findIfRegexMatches(Element element, JSONObject json) {
		String path = json.getString("xpath");
		String pattern = json.getString("pattern");
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(path);
		Element foundElement = (Element) xp.evaluateFirst(element);
		
		return (foundElement == null) ? false : foundElement.getTextNormalize().matches(pattern);
	}	

	/* 
	 *	function to find properties context based on provided paths in stucco_ontology.json 
	 *	and add found properties to new json vertex 
	 */
	private JSONObject constructVertex(Element element, String vertexType) {
		JSONObject newVertex = new JSONObject();
		if (!ConfigFileLoader.getVertexOntology(vertexType).has("properties")) {
			System.out.println(ConfigFileLoader.getVertexOntology(vertexType).toString(2));
			print(element);
		}
		JSONObject properties = ConfigFileLoader.getVertexOntology(vertexType).getJSONObject("properties");
		for (Object property : properties.keySet()) {
			String propertyName = property.toString();
			JSONObject propertyInfo = properties.getJSONObject(propertyName);
			if (propertyInfo.has("xpath")) {
				Object content = getElementContent(element, propertyInfo);
				if (content != null) {
					newVertex.put(propertyName, content);
				}
			} else {
				if (propertyInfo.has("applyFunction")) {
					String applyFunction = propertyInfo.getString("applyFunction");
					Object content = null;
					if (applyFunction.equals("getElementDescriptionList")) {
						content = getElementDescriptionList(element);
					} else if (applyFunction.equals("getElementShortDescriptionList")) {
						content = getElementShortDescriptionList(element);
					}
					if (content != null) {
						newVertex.put(propertyName, content);
					}
				} 
					//else if (!propertyName.equals("vertexType")) {
					//logger.error("Could not find xpath or applyFunction for " + vertexType + ", property: " + propertyName + "!");
					//}
			}
		}
		JSONObject observableTypeInfo = getObservableTypeInfo(element);
		if (observableTypeInfo != null) {
			newVertex.put("observableType", observableTypeInfo.getString("typeName"));
			newVertex.put("name", getObservableName(element, observableTypeInfo));
			// for now it is only observable with even has alias and observable composition; 
			if (observableTypeInfo.has("aliasPath")) {
				newVertex.put("alias", getObservableAlias(element, observableTypeInfo));
			}
		}
		newVertex.put("sourceDocument", new XMLOutputter().outputString(element).replaceAll("\\s\\s+", ""));
		newVertex.put("vertexType", vertexType);
		// malware and campaign can have multiple names, so we put all of them into alias field first, and then move one to name field
		if (vertexType.equals("Malware") || vertexType.equals("Campaign")) {
			if (newVertex.has("alias")) {
				Set<Object> alias = (HashSet<Object>) newVertex.get("alias");
				Iterator<Object> iterator = alias.iterator();
				Object name = iterator.next();
				iterator.remove();
				newVertex.put("name", name);
				if (alias.size() == 0) {
					newVertex.remove("alias");
				}
				
				return newVertex;
			}
		}
		if (!newVertex.has("name")) {
			newVertex.put("name", element.getAttributeValue("id"));
		}

		return newVertex;
	}

	/* 
	 *	function helper: finds element's content based on provided xpath;
	 *	used in construction of properties of new json vertex 
	 */
	private Object getElementContent(Element element, JSONObject propertyInfo) {
		String xpath = propertyInfo.optString("xpath");
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(xpath);
		String pattern = propertyInfo.optString("pattern");
		if (propertyInfo.get("cardinality").equals("single")) {
			/* checking for cardinality and no pattern (content will be not a combination of contents from different elements),
			   then limit xpath search to first found element, so it will not continue looking */
			if (pattern.isEmpty()) { 
				Element foundElement = (Element) xp.evaluateFirst(element);
				return (foundElement == null) ? null : processElementContent(foundElement, propertyInfo);
			} else {
				List<Element> foundElementList = (List<Element>) xp.evaluate(element);
				if (foundElementList.isEmpty()) {
					return null;
				}
				/* this case is for composite propertyValue with pattern; like cpe with part, vendor, product, etc
				   which require content of a set of elements arranged according a pattern */
				boolean componentsFound = false;
				Object propertyValue = null;
				for (Element foundElement : foundElementList) {
					String elementName = foundElement.getName();
					propertyValue = processElementContent(foundElement, propertyInfo);
					if (propertyValue == null) {
						pattern = pattern.replace(elementName, ""); 
					} else {
						pattern = pattern.replace(elementName, propertyValue.toString()); 
						componentsFound = true;
					}
				}
				return (pattern.isEmpty() || !componentsFound) ? null : pattern;
			}
		} else { /* this is a case when cardinality = set */
			/* testing for cardinality = set, and returning a set of resulting values */
			List<Element> foundElementList = (List<Element>) xp.evaluate(element);
			if (foundElementList.isEmpty()) {
				return null;
			}
			if (pattern.isEmpty()) {
				Set<Object> set = new HashSet<Object>();
				for (Element foundElement : foundElementList) {
					Object propertyValue = processElementContent(foundElement, propertyInfo);
					if (propertyValue != null) {
						set.add(propertyValue);
					}
				}
			//	return (set.isEmpty()) ? null : new JSONArray(set);
				return (set.isEmpty()) ? null : set;
			} else {
				//TODO double check on propertyValue with pattern and cardinality = set ...
				// not sure how to handle those yet, but it should not happen ... here is a check for it
				logger.info("More than one value was found with pattern and set cardinality!!!");
				return null;
			}		
		}
	}

	/* 
	 *	turning element content into vertex properties, such as looking for description, name, etc. 
	 */
	private Object processElementContent(Element foundElement, JSONObject propertyInfo) {
		Object propertyValue = null;
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

		if (propertyValue == null || propertyValue.equals("")) {
			return null;
		}
		/* regex required in cases like differ IP and AddressRange, where besides value everything else is the same */
		if (propertyInfo.has("regex")) {
			String regexPattern = propertyInfo.getString("regex");
			Pattern p = Pattern.compile(regexPattern);
			Matcher m = p.matcher(propertyValue.toString());
			if (m.find()) {
				propertyValue = m.group(1);
			}
		}
		/* required in cases like convert IP to long, etc. */
		if (propertyInfo.has("applyFunction")) {
			if (propertyInfo.getString("applyFunction").equals("ipToLong")) {
				long ipInt = ipToLong(propertyValue.toString()); 
				return ipInt;
			//	propertyValue = String.valueOf(ipInt); 
			} 
		}

		String type = propertyInfo.optString("type");
		switch (type) {
			case "string":
				return propertyValue.toString();
			case "long":
				return Long.valueOf(propertyValue.toString());
			default: 
				return propertyValue;
		}
	}

	/* 
	 *	if during construction of vertex, required element value is not present, but referenced, then 
	 *	we are getting referenced element and recursively looking for a desired value 
	 */
	private String getReferencedElementName(String idref) {
		if (vertices.has(idref)) {
			JSONObject referencedVertex = vertices.getJSONObject(idref);
			return referencedVertex.getString("name");
		} else {
			if (stixElements.containsKey(idref)) {
				Element referencedElement = stixElements.get(idref);
				String referencedVertexType = determineVertexType(referencedElement);
				if (referencedVertexType != null) {
					JSONObject referencedVertex = constructVertex(referencedElement, referencedVertexType);
					// commented out verification, since many times elements do not have all the required fields, 
					// but throwing them away ends up in loss of important connections
					// if (verifyStuccoVertex(referencedVertex)) {
						vertices.put(idref, referencedVertex);
						return referencedVertex.getString("name");
					// } 
				} else {
					logger.info("Could not find vertexType!");
				}
			}
		}
		return null;
	} 

	/* 
	 *	determines if observable is an object, event, or observable composition;
	 *	required to construct fields, associated with those types 
	 */
	private JSONObject getObservableTypeInfo(Element element) {
		String name = element.getName();
		if (!name.equals("Observable")) {
			return null;
		}
		Element object = element.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		if (object == null) {
			Element event = element.getChild("Event", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			if (event != null) {
				return ConfigFileLoader.getObservableType("Event");
			}
			Element observableComposition = element.getChild("Observable_Composition", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			if (observableComposition != null) {
				return ConfigFileLoader.getObservableType("ObservableComposition");
			} 
			
			return null;
		}
		Element properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
		if (properties == null) {
			return null;
		}
		String type = properties.getAttributeValue("type", Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")).split(":")[1];
		if (type != null) {
			return ConfigFileLoader.getObservableType(type);
		}
		return null;
	}

	/* 
	 *	determines name value for most observables based on xpath provided in cybox_ontology.json 
	 */
	private String getObservableName(Element element, JSONObject observableTypeInfo) {
		String namePath = observableTypeInfo.optString("namePath");
		if (namePath == null || namePath.isEmpty()) {
			return null;
		} else {
			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile(namePath);
			String pattern = observableTypeInfo.optString("pattern");
			if (pattern.isEmpty()) {
				Element foundElement = (Element) xp.evaluateFirst(element);
				if (foundElement == null) {
					return null;
				} else {
					String name = null;
					String object_reference = null;
					if ((object_reference = foundElement.getAttributeValue("object_reference")) != null) {
						name = getReferencedElementName(object_reference);
					} else {
						name = foundElement.getTextNormalize();
					}
					return (name == null || name.isEmpty()) ? null : name;
				}
			} else {
				List<Element> foundElementList = (List<Element>) xp.evaluate(element);
				String propertyValue = null;
				for (Element foundElement : foundElementList) {
					if (foundElement.getAttribute("object_reference") != null) {
						String object_reference = foundElement.getAttributeValue("object_reference");
						propertyValue = getReferencedElementName(object_reference);
					} else {
						propertyValue = foundElement.getTextNormalize();
					}
					pattern = (propertyValue.isEmpty()) ? pattern.replace(foundElement.getName(), "") : pattern.replace(foundElement.getName(), propertyValue);
				}
				/* cleaning pattern that left after composing software/hardware name with missing cpe components */
				if (observableTypeInfo.get("typeName").equals("Product")) {
					pattern = cleanCpeName(pattern);
				}
				return pattern;
			}
		}
	}

  /* 
   *	function in used in cases like observable composition, where vertex does not have a unique name,
   *	but it can have alias with names of all the objects it is composed of;
   *	required for alignment/comparison 
   */
	private Object getObservableAlias(Element element, JSONObject observableTypeInfo) {
		Set<Object> set = new HashSet<Object>();
		String aliasPath = observableTypeInfo.getString("aliasPath");
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(aliasPath);
		List<Element> list = (List<Element>) xp.evaluate(element);
		for (Element foundElement : list) {
			if (foundElement.getAttribute("idref") != null) {
				String content = getReferencedElementName(foundElement.getAttributeValue("idref"));
				set.add(content);
			} else {
				String content = foundElement.getTextNormalize();
				if (!content.isEmpty()) {
					set.add(foundElement.getTextNormalize());
				}
			}
		}

		return (set.isEmpty()) ? null : set;
	}

	/* 
	 *	finds a relationship based on provided, if relationship is not provided, 
	 *	it is looking for the path of referenced element to try to determine it based on rules from stucc_ontology;
	 *	if related path is not found, then looking in graph_config 
	 */
	private String getRelationship(Element refElement, String outVertID, String inVertID) {
		String outVertType = vertices.getJSONObject(outVertID).getString("vertexType");
		String inVertType = vertices.getJSONObject(inVertID).getString("vertexType");
		String refPath = refElement.getQualifiedName();
		while (refElement.getParentElement() != null) {
			refElement = refElement.getParentElement();
			refPath = refElement.getQualifiedName() + "/" + refPath;
		}
		JSONObject outVertConfig = ConfigFileLoader.getVertexOntology(outVertType);
		if (outVertConfig.has("edges")) {
			JSONObject edges = outVertConfig.getJSONObject("edges");
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

	/* 
	 *	testing if elements id equals idref, or if element contains child with id equals idref;
	 *	required to construct an edges 
	 */
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

	private JSONObject constructNewEdge(String outVertID, String inVertID, String relationship) {
		JSONObject newEdge = new JSONObject();
		newEdge.put("inVertID", inVertID);
		newEdge.put("outVertID", outVertID);
		newEdge.put("relation", relationship);

		return newEdge;
	}	

	private Object getElementDescriptionList(Element element) {
		Set<Object> descriptionList = getElementDescriptionList(element, "Description");
		
		return (descriptionList.isEmpty()) ? null : descriptionList;
	}

	private Object getElementShortDescriptionList(Element element) {
		Set<Object> descriptionList = getElementDescriptionList(element, "Short_Description");

		return (descriptionList.isEmpty()) ? null : descriptionList;
	}

	/* collecting all the descriptions from xml element into list for default element to vertex convertion */
	private Set<Object> getElementDescriptionList(Element element, String descriptionType) {
		Set<Object> descriptionList = new HashSet<Object>();
		if (element.getName().equals(descriptionType)) {
			String content = element.getTextNormalize();
			if (!content.isEmpty()) {
				descriptionList.add(content);
			}
		} else {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				descriptionList.addAll(getElementDescriptionList(child, descriptionType));
			}	
		}

		return descriptionList;
	}

	/* 
	 *	helper function: turns ip string to long; required as a property for ip and addressRange vertices 
	 */
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
}
