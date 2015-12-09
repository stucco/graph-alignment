package alignment.alignment_v2;

import java.util.List;
import java.util.ArrayList;

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

public class GraphConstructor extends PreprocessSTIXwithJDOM2 {
		
	private String STIX_ONTOLOGY = "resources/ontology/stix_ontology.json";
	private String VERTEX_TYPE_CONFIG = "resources/ontology/vertex_type_config.json";

	private JSONObject graph = null;
	private JSONObject ontology = null;
	private JSONObject vertexTypeConfig = null;

	public GraphConstructor() {
		graph = new JSONObject();
		
		try {
			/* required to map new incomming stix xml to vertesType (like is it IP, Port, etc ?) */
			vertexTypeConfig = new JSONObject(new String(Files.readAllBytes(Paths.get(VERTEX_TYPE_CONFIG))));
			/* required to construct a graph, to do all the comparisons, and stix xml editing */
			ontology = new JSONObject(new String(Files.readAllBytes(Paths.get(STIX_ONTOLOGY))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/* function to take stix xml as a string, 
	   normalize it (split into main components: Observable, TTP, etc.), 
	   and pass it to farther conversion to vertex */
	public void constructGraph(String stix) {
		normalizeSTIXPackage(stix);
		Document stixDoc = getSTIXDocument();
	//	printElement(stixDoc.getRootElement());
	//	validate(getSTIXPackage());
		constructGraphFromDocument(stixDoc);
	}
	
	/* takes normalized stix xml as a Document, using xpath to find elements and then tern them into vertices */
	private void constructGraphFromDocument(Document stixDoc) {	
		String path = null;
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = null;

		path = "/*[local-name() = 'STIX_Package']/*[local-name() = 'Exploit_Targets']/*[local-name() = 'Exploit_Target']";
		xp = xpfac.compile(path);
		List<Element> etList = (List<Element>) xp.evaluate(stixDoc);
		for (Element et : etList) {
			turnElementIntoVertex(et);
		}	
		
		path = "/*[local-name() = 'STIX_Package']/*[local-name() = 'TTPs']/*[local-name() = 'TTP']";
		xp = xpfac.compile(path);
		List<Element> ttpList = (List<Element>) xp.evaluate(stixDoc);
		for (Element ttp : ttpList) {
			turnElementIntoVertex(ttp);
		}	
		
		path = "/*[local-name() = 'STIX_Package']/*[local-name() = 'Observables']/*[local-name() = 'Observable']";
		xp = xpfac.compile(path);
		List<Element> observableList = (List<Element>) xp.evaluate(stixDoc);
		for (Element observable : observableList) {
		//	System.out.println("sendign observable = ");
		//	printElement(observable);
			turnElementIntoVertex(observable);
		}	
	}

	private JSONObject turnElementIntoVertex(Element element) {
		String vertexType = determineVertexType(element);
		JSONObject newVertex = constructNewVertex(element, vertexType);
		System.out.println(newVertex.toString(2));

		return newVertex;
	}

	/* function to traverse vertex_type_config.json stored into vertexTypeConfig
	   to determine what is a vertexType of this stix element */
	private String determineVertexType(Element element) {
		for (Object keyObject : vertexTypeConfig.keySet()) {
			String key = keyObject.toString();
			JSONObject possibleType = vertexTypeConfig.getJSONObject(key);
			if (possibleType.has("path")) {
				if (findIfPathExists(element, possibleType.getString("path"))) {
					System.out.println("Found vertexType = " + key);
					return key;
				}
			} else if (possibleType.has("regex")) {
				if (findIfRegexMatches(element, possibleType.getJSONObject("regex"))) {
					System.out.println("Found vertexType = " + key);
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
		JSONArray allOf = vertOntology.getJSONArray("allOf");
		for (int i = 0; i < allOf.length(); i++) {
			JSONObject property = allOf.getJSONObject(i);
			if (property.has("properties")) {
				JSONObject properties = property.getJSONObject("properties");
				for (Object nameObject : properties.keySet()) {
					String nameString = nameObject.toString();
				//	System.out.println(nameString + " = " + properties.get(nameString));
					JSONObject vertProperty = properties.getJSONObject(nameString);
					if (vertProperty.has("xpath")) {
					//	System.out.println("xpath = " + vertProperty.get("xpath"));
						Object content = getElementContent(element, vertProperty.getString("xpath"));
						newVertex.put(nameString, content);
				//		System.out.println(nameString + " = " + content);
					}
				}
			} else {
				System.out.println("$ref = " + property.get("$ref"));
			}
		}

		newVertex.put("sourceDocument", new XMLOutputter().outputString(element));
		newVertex.put("vertexType", vertexType);
		return (testRequiredFields(newVertex, vertexType)) ? newVertex : null;
	}

	/* function helper; finds element's content based on provided xpath;
	   used in construction of properties of new json vertex */
	private Object getElementContent(Element element, String xpath) {
		XPathFactory xpfac = XPathFactory.instance();
		XPathExpression xp = xpfac.compile(xpath);
		Element foundElement = (Element) xp.evaluateFirst(element);
		System.out.println(foundElement);		

		return (foundElement == null) ? null : foundElement.getTextNormalize();	
	}
		
	private boolean testRequiredFields(JSONObject newVertex, String vertexType) {
		JSONArray requiredFields = ontology.getJSONObject("definitions").getJSONObject(vertexType).getJSONArray("required");
		for (int i = 0; i < requiredFields.length(); i++) {
			String requiredField = requiredFields.getString(i);
			if (!newVertex.has(requiredField)) {
				return false;
			}
		}

		return true;
	}
}
