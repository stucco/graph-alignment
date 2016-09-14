package gov.ornl.stucco;

import gov.ornl.stucco.preprocessors.PreprocessSTIX.Vertex;

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

	/* 
	 *	vertices are stored as a key/value, or id/vertex, 
	 *	because search jsonObject is faster and easier, than xml 
	 */
	private JSONObject graph = null;
	private JSONObject vertices = null;
	private JSONArray edges = null;

	private Map<String, Vertex> stixElements = null;
	private Map<String, Map<Object, String>> vertBookkeeping = null;
	private Map<String, String> duplicateMap = null;

	public String print(Element e) {
		XMLOutputter xmlOutputter = new XMLOutputter(Format.getPrettyFormat());
		System.out.println(xmlOutputter.outputString(e));

		return xmlOutputter.outputString(e);
	}

	public GraphConstructor() {
		logger = LoggerFactory.getLogger(GraphConstructor.class);
	}

	public JSONObject constructGraph(Map<String, Vertex> stixElements) {
		if (stixElements == null) {
			return null;
		} else {
			this.stixElements = stixElements;
			graph = new JSONObject();
			vertices = new JSONObject();
			edges = new JSONArray();
			vertBookkeeping = new HashMap<String, Map<Object, String>>();
			duplicateMap = new HashMap<String, String>();
			constructGraph();
		}

		return graph;
	}

	private void constructGraph() {	
		/* turning elements into vertices first, so if any of them are not valid or 
		   do not contain required fields we would not create edges for those vertices */
		JSONObject vertexTypes = ConfigFileLoader.stuccoOntology.getJSONObject("properties").getJSONObject("vertices").getJSONObject("items");
		for (Map.Entry<String, Vertex> entry : stixElements.entrySet()) {
			/* some vertices are created out of order; example is when required field value is in references element */
			String id = entry.getKey();
			if (vertices.has(id)) {
				continue;
			}
			Vertex v = entry.getValue();
			constructSubgraph(id, v, vertexTypes);
		}
		graph.put("vertices", vertices);
		graph.put("edges", edges);
	}

	private String constructSubgraph(String id, Vertex v, JSONObject vertexTypes) {	
		String vertexType = determineVertexType(v, vertexTypes); 
		JSONObject newVertex = constructVertex(v, vertexType);
		String outVertID = checkForDuplicate(id, vertexType, newVertex);
		
		for (String path : v.referencePaths.keySet()) {
			List<String> list = v.referencePaths.get(path);
			for (String idref : list) {
				String inVertID = null;
				String inVertexType = null;
				if (vertices.has(idref)) {
					inVertID = idref;
				} else if (stixElements.containsKey(idref)) {
					Vertex inV = stixElements.get(idref);
					inVertID = constructSubgraph(idref, inV, vertexTypes);
					if (!inVertID.equals(idref)) {
						updateXMLString(vertices.getJSONObject(outVertID), idref, inVertID);
					}
				} else if (duplicateMap.containsKey(idref)) {
					inVertID = duplicateMap.get(idref);
					updateXMLString(vertices.getJSONObject(outVertID), idref, inVertID);
				} else {
					logger.debug("Could not find outVertex to construct an edge with outVertID = " + outVertID);

					return outVertID;
				}
				
				if (inVertID != null) {
					inVertexType = vertices.getJSONObject(inVertID).getString("vertexType");
					String relationship = getRelationship(vertexType, inVertexType);
					if (relationship == null) {
						logger.debug("Find relationship between outVertType = " + vertexType + " and inVertType = " + inVertexType);
						relationship = "Related_" + inVertexType;
					}
					JSONObject newEdge = constructNewEdge(outVertID, inVertID, relationship);
					edges.put(newEdge);	
				}
			}
		}

		return outVertID;
	}

	/* 
	 *	finds a relationship based on provided, if relationship is not provided, 
	 *	it is looking for the path of referenced element to try to determine it based on rules from stucc_ontology;
	 *	if related path is not found, then looking in graph_config 
	 */

	//TODO: change ontology to have inVertType as a key insteadof relashionship
	private String getRelationship(String outVertType, String inVertType) {
		String relationship = null;
		JSONObject outVertConfig = ConfigFileLoader.getVertexOntology(outVertType);
		if (outVertConfig.has("edges")) {
			JSONObject edges = outVertConfig.getJSONObject("edges");
			if (edges.has(inVertType)) {
				relationship = edges.getJSONObject(inVertType).getString("relation");
			}
		}

		return relationship;
	}

	private String checkForDuplicate(String id, String vertexType, JSONObject newVertex) {
		boolean duplicate = false;
		//TODO: add additional comparison for malware and campaign based on their alias
		//TODO: merge properties of duplicates
		String type = (newVertex.has("observableType")) ? newVertex.getString("observableType") : vertexType;
		if (vertBookkeeping.containsKey(type)) {
			Map<Object, String> vertNameBookkeeping = vertBookkeeping.get(type);
			Object vertName = newVertex.get("name");
			if (vertNameBookkeeping.containsKey(vertName)) {
				String duplicateId = vertNameBookkeeping.get(vertName);
				duplicateMap.put(id, duplicateId);
				JSONObject existingVertex = vertices.getJSONObject(duplicateId);
				alignVertProps(newVertex, existingVertex);

				return duplicateId; 
			} else {
				vertNameBookkeeping.put(vertName, id);
			}
		} else {
			Map<Object, String> vertNameBookkeeping = new HashMap<Object, String>();
			vertNameBookkeeping.put(newVertex.get("name"), id);
			vertBookkeeping.put(type, vertNameBookkeeping);
		}

		vertices.put(id, newVertex);

		return id;
	}

	private void alignVertProps(JSONObject newVertex, JSONObject existingVertex) {
		JSONObject vertProperties = ConfigFileLoader.getVertexOntology(newVertex.getString("vertexType")).getJSONObject("properties");
		for (Object keyObject : vertProperties.keySet()) {
			String key = keyObject.toString();
			if (!newVertex.has(key)) {
				continue;
			}
			// TODO: removed sourceDocument alignment since all stix elements must be in particular order
			// to add new element, it's index must be known; 
			// it would require massive config file or use of stix java library; both options are computationally expensive
			if (key.equals("sourceDocument")) {
				// TODO: come up with an ideo of how to combine xml ... since in stix all elements must be in particular order
				//	maybe when stix will move to JSON it will be easier
				continue;
			} else {
				String cardinality = vertProperties.getJSONObject(key).getString("cardinality");
				if (cardinality.equals("set")) {
					Set<Object> set = (HashSet<Object>) newVertex.get(key);
					if (key.equals("alias")) {
						set.add(newVertex.getString("name"));
						set.remove(existingVertex.getString("name"));
					}
					if (existingVertex.has(key)) {
						set.addAll((HashSet<Object>) existingVertex.get(key));
					} 
					/* MUST be casted to Object in order to keep it as a set, otherwise it will convert it to JSONArray */
					existingVertex.put(key, (Object)set);
				}
			}
		}
	}

	/* 	
	 *	updating xml strings idref to match new vertex id, if duplicate was detected
	 */ 
	private void updateXMLString(JSONObject vertex, String oldIdref, String newIdref) {
		String sourceDocument = vertex.getString("sourceDocument");
		//TODO: should it be replaceAll? kept it as replaceFirst for now ...
		sourceDocument = sourceDocument.replaceFirst(oldIdref, newIdref);
		vertex.put("sourceDocument", sourceDocument);
	}

	/* 
	 *	function to traverse graph_config.json 
	 *	to determine what is a vertexType of this stix element 
	 */
	private String determineVertexType(Vertex v, JSONObject vTypesDef) {
		String vertexType = v.type;
		JSONObject vTypeDef = vTypesDef.getJSONObject(v.type);
		if (vTypeDef.has("items")) {
			JSONObject vSubTypesDef = vTypeDef.getJSONObject("items");
			for (Object key : vSubTypesDef.keySet()) {
				String subType = key.toString();
				JSONObject vSubTypeDef = vSubTypesDef.getJSONObject(subType);
				String path = vSubTypeDef.getString("path");
				if (v.type.equals("Observable")) {
					if (v.contentPaths.containsKey(path)) {
						boolean found = true;
						if (vSubTypeDef.has("observableType")) {
							String observableType = vSubTypeDef.getString("observableType");
							if (!observableType.equals(v.observableType)) {
								continue;
							}
						}
						if (vSubTypeDef.has("pattern") && found) {
							String pattern = vSubTypeDef.getString("pattern");
							String content = v.contentPaths.get(path).get(0).toString();
							if (content.matches(pattern)) {
								vertexType = subType;
								break;
							}	
						}
					}
				} else {
					for (String contentPath : v.contentPaths.keySet()) {
						if (contentPath.startsWith(path)) {
							return subType;
						}
					}
				}
			}
		} 

		return vertexType;
	}

	/* 
	 *	function to find properties context based on provided paths in stucco_ontology.json 
	 *	and add found properties to new json vertex 
	 */
	private JSONObject constructVertex(Vertex v, String vertexType) {
		JSONObject newVertex = new JSONObject();
		JSONObject properties = ConfigFileLoader.getVertexOntology(vertexType).getJSONObject("properties");
		for (String property : (Set<String>)properties.keySet()) {
			JSONObject propertyInfo = properties.getJSONObject(property);
			if (propertyInfo.has("path")) {
				Object content = getElementContent(v, propertyInfo);
				if (content != null) {
					newVertex.put(property, content);
				}
			} else {
				if (propertyInfo.has("applyFunction")) {
					String applyFunction = propertyInfo.getString("applyFunction");
					Object content = null;
					if (applyFunction.equals("getElementDescriptionList")) {
						content = getDescriptionList(v);
					} else if (applyFunction.equals("getElementShortDescriptionList")) {
						content = getShortDescriptionList(v);
					}
					if (content != null) {
						newVertex.put(property, content);
					}
				}
			}
		}

		if (v.observableType != null) {
			JSONObject observableTypeInfo = ConfigFileLoader.getObservableType(v.observableType);

			if (observableTypeInfo != null) {
				newVertex.put("observableType", observableTypeInfo.getString("typeName"));
				Object name = getObservableName(v, observableTypeInfo);
				if (newVertex.get("observableType").equals("Product")) {
					newVertex.put("name", cleanCpeName(name.toString()));
				} else {
					newVertex.put("name", name);
				}
				// for now it is only observable with even has alias and observable composition; 
				if (observableTypeInfo.has("aliasPath")) {
					newVertex.put("alias", getObservableAlias(v, observableTypeInfo));
				}
			}
		}
		newVertex.put("sourceDocument", v.xml);
		newVertex.put("vertexType", vertexType);
		//System.out.println(newVertex.toString(2));
		// malware and campaign can have multiple names, so we put all of them into alias field first, and then move one to name field
		/*
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
		*/

		if (!newVertex.has("name")) {
			newVertex.put("name", v.id);
		}
		return newVertex;
	}

	/* 
	 *	function helper: finds element's content based on provided xpath;
	 *	used in construction of properties of new json vertex 
	 */
	private Object getElementContent(Vertex v, JSONObject propertyInfo) {
		String pattern = propertyInfo.optString("pattern");
		JSONArray paths = propertyInfo.getJSONArray("path");
		if (propertyInfo.get("cardinality").equals("single")) {
			if (pattern.isEmpty()) {
				Object content = null;
				if (paths.length() > 1) {
					logger.debug("MULTIPLE PATHS FOR PROPERTY OF SINGLE CARDINALITY: " + propertyInfo);
				}
				String path = paths.getString(0);
				if (v.contentPaths.containsKey(path)) {
					content = v.contentPaths.get(path).get(0);
				} else if (v.referencePaths.containsKey(path)) {
					content = getReferencedElementName(v.referencePaths.get(path).get(0));
				}

				return (content == null) ? content : processContent(content, propertyInfo);

			} else {
				boolean componentsFound = false;
				for (int i = 0; i < paths.length(); i++) {
					String path = paths.getString(i);
					if (v.contentPaths.containsKey(path)) {
						List<Object> list = v.contentPaths.get(path);
						Object content = (list == null) ? "" : list.get(0);
						String[] p = path.split("/");
						pattern = pattern.replace(p[p.length - 1], content.toString());
						componentsFound = (componentsFound || !content.toString().isEmpty());
					} else if (v.referencePaths.containsKey(path)) {
						Object content = getReferencedElementName(v.referencePaths.get(path).get(0));
						String[] p = path.split("/");
						pattern = pattern.replace(p[p.length - 1], content.toString());
						componentsFound = (componentsFound || !content.toString().isEmpty());
					}
				}
				return (pattern.isEmpty() || !componentsFound) ? null : pattern;	
			}
		} else {
			Set<Object> content = new HashSet<Object>();
			for (int i = 0; i < paths.length(); i++) {
				String path = paths.getString(i);
				if (v.contentPaths.containsKey(path)) {
					List<Object> list = v.contentPaths.get(path);
					for (Object value : list) {
						content.add(processContent(value, propertyInfo));
					}
				}
				if (v.referencePaths.containsKey(path)) {
					List<String> idrefList = v.referencePaths.get(path);
					for (String idref : idrefList) {
						Object value = getReferencedElementName(idref);
						if (value != null) {
							content.add(processContent(value, propertyInfo));
						}
					}
				}
			}

			return content;
		}
	}

	/* 
	 *	turning element content into vertex properties, such as looking for description, name, etc. 
	 */
	private Object processContent(Object propertyValue, JSONObject propertyInfo) {
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

	private Object getReferencedElementName(String idref) {
		Object name = null;
		if (vertices.has(idref)) {
			JSONObject vertex = vertices.getJSONObject(idref);
			name = vertex.get("name");
		} else {
			if (stixElements.containsKey(idref)) {
				Vertex v = stixElements.get(idref);
				JSONObject vertexTypes = ConfigFileLoader.stuccoOntology.getJSONObject("properties").getJSONObject("vertices").getJSONObject("items");
				idref = constructSubgraph(idref, v, vertexTypes);
				name = vertices.getJSONObject(idref).get("name");
			}
		}

		return name;
	}

	private Object getDescriptionList(Vertex v) {
		Set<Object> description = new HashSet<Object>();
		for (String path : v.contentPaths.keySet()) {
			if (path.endsWith("Description")) {
				description.addAll(v.contentPaths.get(path));
			}
		}

		return description;
	}

	private Object getShortDescriptionList(Vertex v) {
		Set<Object> shortDescription = new HashSet<Object>();
		for (String path : v.contentPaths.keySet()) {
			if (path.endsWith("Short_Description")) {
				shortDescription.addAll(v.contentPaths.get(path));
			}
		}

		return shortDescription;
	}

	/* 
	 *	determines name value for most observables based on xpath provided in cybox_ontology.json 
	 */
	private Object getObservableName(Vertex v, JSONObject observableTypeInfo) {
		JSONArray namePaths = observableTypeInfo.optJSONArray("namePath");
		if (namePaths == null) {
			return null;
		} else {
			String pattern = observableTypeInfo.optString("pattern");
			if (pattern.isEmpty()) {
				Object content = null;
				for (int i = 0; i < namePaths.length(); i++) {
					String path = namePaths.getString(i);
					if (v.contentPaths.containsKey(path)) {
						return v.contentPaths.get(path).get(0);
					} else if (v.referencePaths.containsKey(path)) {
						List<String> list = v.referencePaths.get(path);
						if (list.size() > 1) {
							logger.debug("List of idRef is more tham one for pattern: " + path);
						}
						Object e = getReferencedElementName(list.get(0));

						return e;
					}
				}
			} else {
				boolean componentsFound = false;
				for (int i = 0; i < namePaths.length(); i++) {
					String path = namePaths.getString(i);
					if (v.contentPaths.containsKey(path)) {
						List<Object> list = v.contentPaths.get(path);
						Object content = (list == null) ? "" : list.get(0);
						String[] p = path.split("/");
						pattern = pattern.replace(p[p.length - 1], content.toString());
						componentsFound = (componentsFound || !content.toString().isEmpty());
					} else if (v.referencePaths.containsKey(path)) {
						Object content = getReferencedElementName(v.referencePaths.get(path).get(0));
						String[] p = path.split("/");
						pattern = pattern.replace(p[p.length - 1], content.toString());
						componentsFound = (componentsFound || !content.toString().isEmpty());
					}
				}
				return pattern;
			}
			/* cleaning pattern that left after composing software/hardware name with missing cpe components */
			//if (observableTypeInfo.get("typeName").equals("Product")) {
			//	pattern = cleanCpeName(pattern);
			//}

			return null;
		}
	}

	/* 
   *	function in used in cases like observable composition, where vertex does not have a unique name,
   *	but it can have alias with names of all the objects it is composed of;
   *	required for alignment/comparison 
   */
	private Object getObservableAlias(Vertex v, JSONObject observableTypeInfo) {
		Set<Object> set = new HashSet<Object>();
		String aliasPath = observableTypeInfo.getString("aliasPath");
		if (v.contentPaths.containsKey(aliasPath)) {
			set.addAll(v.contentPaths.get(aliasPath));
		} else if (v.referencePaths.containsKey(aliasPath)) {
			List<String> aliasIdref = v.referencePaths.get(aliasPath);
			for (String idref : aliasIdref) {
				Object name = getReferencedElementName(idref);
				if (name != null) {
					set.add(name);
				}
			}
		}

		return (set.isEmpty()) ? null : set;
	}

	private JSONObject constructNewEdge(String outVertID, String inVertID, String relationship) {
		JSONObject newEdge = new JSONObject();
		newEdge.put("inVertID", inVertID);
		newEdge.put("outVertID", outVertID);
		newEdge.put("relation", relationship);

		return newEdge;
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
