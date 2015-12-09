package alignment.alignment_v2;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.File;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Set;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.XML;
import org.junit.Test;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException; 
import org.xml.sax.SAXParseException;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Attribute;
import org.jdom2.Namespace;
import org.jdom2.xpath.*;
import org.jdom2.filter.Filters;

import org.apache.commons.io.FileUtils;

public class PreprocessSTIXWithJDOMTest extends PreprocessSTIXwithJDOM2 {
	
	private Map<String, String> parentElementMap = getParentElementMap();
	private Map<String, Element> stixElementMap = getStixElementMap();

	private boolean traverseNormalizedElements(Element initElement, Element receivedElement, Element receivedRoot) {
		System.out.println("******* Comparing " + initElement.getQualifiedName() + " and " + receivedElement.getQualifiedName() + " *******");
		String content1 = initElement.getTextNormalize();
		String content2 = receivedElement.getTextNormalize();
		if (!content1.isEmpty() || !content2.isEmpty()) {
 			return (testContent(initElement, receivedElement));
		} else {
			if (!compareAttributes(initElement, receivedElement)) {
				return false;
			}

			List<Element> l1 = initElement.getChildren();

			for (Element e1 : l1) {
				String e1Name = e1.getName();
				Namespace e1Ns = e1.getNamespace();
				if (stixElementMap.containsKey(e1Name) 
						&& !e1Ns.equals(stixElementMap.get(e1Name).getNamespace()) 
						&& e1.getAttribute("idref") == null) {
					List<Element> l2 = receivedElement.getChildren(e1Name, e1Ns);
					System.out.println("******************************************************************");
					System.out.println("******** For " + e1.getQualifiedName() + " do a special comparison");
					System.out.println("******************************************************************");
					if (!compareRefactoredElements(e1, l2, receivedRoot)) {
						return false;
					}
				} else {
					List<Element> l2 = receivedElement.getChildren(e1Name, e1Ns);
					if (l2.size() > 1) {
						boolean found = false;
						for (Element e2 : l2) {
							if (traverseNormalizedElements(e1, e2, receivedRoot)) {		
								found = true;
								break;
							} else {
								System.out.println("Keep serching for a match .... ");
							}
						}
						if (!found) {
							System.out.println("Could not find a match for " + e1.getQualifiedName() + " .... ");
							return false;
						} else {
							System.out.println("Found a match amond multiple elements");
						}
					} else if (l2.size() == 1) {
						traverseNormalizedElements(e1, l2.get(0), receivedRoot);
					} else if (l2.size() == 0) {
						return false;
					}
				}
			}
		}
		return true;
	}
					
	boolean compareRefactoredElements(Element e1, List<Element> l2, Element root) {
		String e1Name = e1.getName();
		Namespace e1Ns = e1.getNamespace();
		Element e2 = root.getChild(parentElementMap.get(e1Name), Namespace.getNamespace("stix", "http://stix.mitre.org/stix-1"));
		List<Element> potentialMatchList = e2.getChildren(stixElementMap.get(e1Name).getName(), stixElementMap.get(e1Name).getNamespace());
		for (Element newChild : potentialMatchList) {
			if (traverseNormalizedElements(e1, newChild, root)) {
				System.out.println("Found a match .... now testing id = idref");
				String id = newChild.getAttributeValue("id");
				for (Element refE : l2) {
					String idref = refE.getAttributeValue("idref");
					if (id.equals(idref)) {
						System.out.println("Found a matching idref");
						return true;
					}
				}
			}
		}

		return false;
	}
	
	private boolean testContent(Element initElement, Element receivedElement) {
		String content1 = initElement.getTextNormalize();
		boolean match = true;
		if (!content1.isEmpty()) {
			System.out.println("Testing " + initElement.getQualifiedName() + " Content");
			System.out.println(" - Looking for: " + content1);
			String content2 = receivedElement.getTextNormalize();
			if (!content1.equals(content2)) {
				System.out.println("[Could not match " + content1 + " .... returning]");
				match = false;
			}
			if (!compareAttributes(initElement, receivedElement)) {
				System.out.println("[Could not match Attributes .... returning]");
				match = false;
			}
			System.out.println("Testing " + initElement.getQualifiedName() + " Namespace");
			System.out.println(" - Looking for: " + initElement.getNamespace().toString());
			if (!initElement.getNamespace().equals(receivedElement.getNamespace())) {
				System.out.println("[Could not match " + initElement.getNamespace().toString() + " .... returning]");
				match = false;
			}
		}
		return match;	
	}
	
	private boolean compareAttributes(Element e1, Element e2) {
		System.out.println("Testing " + e1.getQualifiedName() + " Attributes");
		List<Attribute> a1 = e1.getAttributes();
		List<Attribute> a2 = e2.getAttributes();
		if (!a1.isEmpty() && a1.size() == a2.size()) {
			for (Attribute a : a1) {		
				System.out.println(" - Looking for: " + a.toString());
				if (a.getName().equals("idref")) {
					Attribute attr = (e2.getAttribute("idref") == null) ? e2.getAttribute("id") : null;
					if (attr == null) {
						System.out.println("[Could not match " + a.toString() + " .... returning]");
						return false;
					} 
					if (!a.getValue().equals(attr.getValue())) {
						System.out.println("[Could not match " + a.toString() + " .... returning]");
						return false;
					}	
				} else {
					Attribute attr = e2.getAttribute(a.getName(), a.getNamespace());
					if (attr == null) {
						System.out.println("[Could not match " + a.toString() + " .... returning]");
						return false;
					}
					if (!attr.getValue().equals(a.getValue())) {
						System.out.println("[Could not match " + a.toString() + " .... returning]");
						return false;
					}
				} 
			}		
		}	
		return true;
	}

	/* methods to compare XML and JSON */
	private boolean traverse(Element element, JSONObject json) {
		List<Element> elementList = element.getChildren();
		for (Element child : elementList) {
			assertTrue(json.has(child.getQualifiedName()));
			if (json.optJSONArray(child.getQualifiedName()) != null) {
				JSONArray array = json.getJSONArray(child.getQualifiedName());
				boolean match = false;
				for (int i = 0; i < array.length(); i++) {
					if (compareElementAndJSON(child, array.getJSONObject(i))) {
						traverse(child, array.getJSONObject(i));
						match = true;
						break;
					}
				}
				if (!match) {
					return false;
				}	
			} else {
				if (!compareElementAndJSON(child, json.getJSONObject(child.getQualifiedName()))) {
					return false;
				} else {
					traverse(child, json.getJSONObject(child.getQualifiedName()));
				}
			}
		}
		return true;
	}

	private boolean compareElementAndJSON(Element element, JSONObject json) {
		System.out.println("******* Testign " + element.getQualifiedName() + " content *******");

		/* attributes */
		List<Attribute> attrList = element.getAttributes();
		if (!attrList.isEmpty()) {
			if (!json.has("attr")) {
				return false;
			}
			Map<String, String> receivedAttrMap = new HashMap<String, String>();
			Map<String, Namespace> receivedAttrNSMap = new HashMap<String, Namespace>();
			JSONArray attrArray = json.getJSONArray("attr");
			for (int i = 0; i < attrArray.length(); i++) {
				JSONObject attrObject = attrArray.getJSONObject(i);
				for (Object attrKey : attrObject.keySet()) {
					String attrName = attrKey.toString();
					String attrContent = attrObject.getJSONObject(attrName).getString("content");
					receivedAttrMap.put(attrName, attrContent);
					if (attrObject.getJSONObject(attrName).has("ns")) {
						JSONObject attrNS = attrObject.getJSONObject(attrName).getJSONObject("ns");
						for (Object prefix : attrNS.keySet()) {
							String prefixString = prefix.toString();
							Namespace receivedNS = Namespace.getNamespace(prefixString, attrNS.getString(prefixString));
							receivedAttrNSMap.put(prefixString, receivedNS);
						}
					}
				}
			}

			System.out.println("Testing " + element.getQualifiedName() + " Attributes");
			Map<String, String> initAttrMap = new HashMap<String, String>();
			Map<String, Namespace> initAttrNSMap = new HashMap<String, Namespace>();
			for (Attribute attr : attrList) {
				System.out.print(" - Looking for: " + attr.toString());
				if (!receivedAttrMap.get(attr.getQualifiedName()).equals(attr.getValue())) {
					return false;
				}
				Namespace attrNs = attr.getNamespace();
				if (!attrNs.getPrefix().isEmpty()) {
					System.out.print(" in Namespace: " + attrNs.toString());
					if (!receivedAttrNSMap.get(attrNs.getPrefix()).equals(attrNs)) {
						return false;
					}
				}
				System.out.println();
			}
			
		}

		/* namespace */
		Namespace rootNs = element.getNamespace();
		if (!rootNs.getPrefix().isEmpty()) {
			if (!json.has("ns")) {
				return false;
			}
			System.out.println("Testing " + element.getQualifiedName() + " Namespace");
			System.out.println(" - Looking for: " + rootNs.toString());
			JSONObject jsonNs = json.getJSONObject("ns");
			if (!jsonNs.get(rootNs.getPrefix()).equals(rootNs.getURI())) {
				return false;
			}
		}

		/* content */
		String elementContent = element.getTextNormalize();
		if (!elementContent.isEmpty()) {
			if (!json.has("content")) {
				return false;
			}	
			System.out.println("Testing " + element.getQualifiedName() + " Content");
			System.out.println(" - Looking for: " + elementContent);
			String jsonContent = json.getString("content");
			if (!elementContent.equals(jsonContent)) {
				return false;
			}
		}
		return true;
	}

	private boolean compareJSONObjects (JSONObject object1, JSONObject object2)	{

		if (object1 == null && object2 != null) return false;
		if (object1 != null && object2 == null) return false;			

		List<String> keysArray1 = new ArrayList<String>();
		List<String> keysArray2 = new ArrayList<String>();

		Iterator<String> keys1 = object1.keys();
		while(keys1.hasNext())	
			keysArray1.add(keys1.next());
		
		Iterator<String> keys2 = object2.keys();
		while(keys2.hasNext())	
			keysArray2.add(keys2.next());
									
		if (keysArray1.size() != keysArray2.size())	return false;
					
		keysArray1.remove("id");
		keysArray1.remove("_id");
		keysArray1.remove("idref");
		keysArray1.remove("timestamp");		
		keysArray1.remove("_outV");
		keysArray1.remove("_inV");

		keysArray2.remove("id");
		keysArray2.remove("_id");
		keysArray2.remove("idref");
		keysArray2.remove("timestamp");		
		keysArray2.remove("_outV");
		keysArray2.remove("_inV");
				
		for (String key: keysArray1)	{
			if (!object2.has(key)) return false; 
		}

		for (int i = 0; i < keysArray1.size(); i++)	{
			String key = keysArray1.get(i);
			if (compare(object1.get(key), object2.get(key)) == false) return false;
		}
						
		return true;
	}
					
	private boolean compareJSONArrays(JSONArray array1, JSONArray array2)	{
		
		if (array1 == null && array2 != null) return false;
		if (array1 != null && array2 == null) return false;			
		if (array1.length() != array2.length())	return false;

		for (int i = 0; i < array1.length(); i++)	{
			Object o1 = array1.get(i);
			boolean equals = false;
			for (int j = 0; j < array2.length(); j++)	{
				Object o2 = array2.get(j);
				equals = compare(o1, o2);
				if (equals == true) break;
			}
			if (equals == false)	return false;
		}
		return true;

	}
			
	private boolean compare	(Object object1, Object object2)	{
									
		if (object1 instanceof JSONArray && object2  instanceof JSONArray)	
			return compareJSONArrays((JSONArray)object1, (JSONArray)object2);
																		
		else if (object1 instanceof JSONObject && object2 instanceof JSONObject)	
			return compareJSONObjects((JSONObject)object1, (JSONObject)object2);
		
		else	return object1.toString().equals(object2.toString());
	}

	/**
	 * Tests normalize stix: Incident with Indicator, Observable, TTP, and ExploitTarget
	 */
	@Test
	public void test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
		try {
			String initialStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:STIX_Source-f0ce33ae-7524-45bb-b397-4a1585ee2cc7\" " +
				"    timestamp=\"2015-10-15T20:11:17.124Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:incident=\"http://stix.mitre.org/Incident-1\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>STIX Source</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:Observable-6700\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Incidents> " +
				"        <stix:Incident  id=\"stucco:Incident-6400\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"incident:IncidentType\"> " +
				"            <incident:Description>Some incident description</incident:Description> " +
				"            <incident:Related_Indicators> " +
				"                <incident:Related_Indicator> " +
				"                    <stixCommon:Indicator id=\"stucco:Indicator-12345\" xsi:type=\"indicator:IndicatorType\"> " +
				"                        <indicator:Description>Some description of Related Indicator</indicator:Description> " +
				"                        <indicator:Observable id=\"stucco:Observable-6789\"> " +
				"                            <cybox:Title>Observable - Title</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Source</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                        </indicator:Observable> " +
				"                        <indicator:Indicated_TTP> " +
				"                            <stixCommon:TTP id=\"stucco:TTP-12345\" xsi:type=\"ttp:TTPType\"> " +
				"                                <ttp:Description>TTP - Description</ttp:Description> " +
				"                                <ttp:Behavior> " +
				"                                    <ttp:Malware> " +
				"                                    <ttp:Malware_Instance> " +
				"                                    <ttp:Type>Malware - Type</ttp:Type> " +
				"                                    <ttp:Name>Malware - Name</ttp:Name> " +
				"                                    </ttp:Malware_Instance> " +
				"                                    </ttp:Malware> " +
				"                                </ttp:Behavior> " +
				"                                <ttp:Exploit_Targets> " +
				"                                    <ttp:Exploit_Target> " +
				"                                    <stixCommon:Exploit_Target " +
				"                                    id=\"stucco:ExploitTarget-12345\" xsi:type=\"et:ExploitTargetType\"> " +
				"                                    <et:Title>ExploitTarget - Title</et:Title> " +
				"                                    </stixCommon:Exploit_Target> " +
				"                                    </ttp:Exploit_Target> " +
				"                                </ttp:Exploit_Targets> " +
				"                            </stixCommon:TTP> " +
				"                        </indicator:Indicated_TTP> " +
				"                    </stixCommon:Indicator> " +
				"                </incident:Related_Indicator> " +
				"            </incident:Related_Indicators> " +
				"        </stix:Incident> " +
				"    </stix:Incidents> " +
				"</stix:STIX_Package> ";

			String expectedStixString = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:STIX_Source-f0ce33ae-7524-45bb-b397-4a1585ee2cc7\" " +
				"    timestamp=\"2015-10-15T20:11:17.124Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:incident=\"http://stix.mitre.org/Incident-1\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>STIX Source</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:Observable-6700\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:Observable-6789\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Source</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator id=\"stucco:Indicator-12345\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Description>Some description of Related Indicator</indicator:Description> " +
				"            <indicator:Observable idref=\"stucco:Observable-6789\"/> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP idref=\"stucco:TTP-12345\" xsi:type=\"ttp:TTPType\"/> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"    <stix:TTPs> " +
				"	<stix:TTP id=\"stucco:TTP-12345\" " +
            			"	     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Description>TTP - Description</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Malware> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type</ttp:Type> " +
				"                        <ttp:Name>Malware - Name</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                </ttp:Malware> " +
				"            </ttp:Behavior> " +
				"            <ttp:Exploit_Targets> " +
				"                <ttp:Exploit_Target> " +
				"                    <stixCommon:Exploit_Target " +
				"                        idref=\"stucco:ExploitTarget-12345\" xsi:type=\"et:ExploitTargetType\"/> " +
				"                </ttp:Exploit_Target> " +
				"            </ttp:Exploit_Targets> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target id=\"stucco:ExploitTarget-12345\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>ExploitTarget - Title</et:Title> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"    <stix:Incidents> " +
				"        <stix:Incident  id=\"stucco:Incident-6400\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"incident:IncidentType\"> " +
				"            <incident:Description>Some incident description</incident:Description> " +
				"            <incident:Related_Indicators> " +
				"                <incident:Related_Indicator> " +
				"                    <stixCommon:Indicator idref=\"stucco:Indicator-12345\" xsi:type=\"indicator:IndicatorType\"/> " +
				"                </incident:Related_Indicator> " +
				"            </incident:Related_Indicators> " +
				"        </stix:Incident> " +
				"    </stix:Incidents> " +
				"</stix:STIX_Package> ";

			JSONObject json = xmlToJson(expectedStixString);

			System.out.println(json.toString(2));

			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();
			assertTrue(normalizedStixPackage.validate());
			
			STIXPackage expectedStixPackage = STIXPackage.fromXMLString(expectedStixString);
			System.out.println("Normalized package = " + normalizedStixPackage.toXMLString(true));
	
			assertTrue(normalizedStixPackage.equals(expectedStixPackage));
			
			JSONObject graphson = preprocessSTIX.xmlToGraphson(normalizedStixPackage.toXMLString());
			JSONArray verts = graphson.getJSONArray("vertices");
			Document stixDocument = preprocessSTIX.getSTIXDocument();

/*			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile("//*[@id]");							
			List<Element> elementList = new ArrayList<Element>(xp.evaluate(stixDocument));
			for (Element element : elementList) {
				if (parentElementMap.containsKey(element.getName())) {
					System.out.println();
					System.out.println("Testing content of " + element.toString());
					String id = element.getAttributeValue("id");
					JSONObject vertex = null;
					for (int i = 0; i < verts.length(); i++) {
						vertex = verts.getJSONObject(i);
						if (vertex.getString("_id").equals(id)) {
							vertex = verts.getJSONObject(i);
							break;
						}
						vertex = null;
					}
					assertNotNull(vertex);
					xp = xpfac.compile(".//*");
					List<Element> eList = new ArrayList<Element>(xp.evaluate(element));
					for (Element e : eList) {
						System.out.println("Working on " + e.toString());
						assertTrue(compareNs(e, vertex));
						if (e.hasAttributes()) {
							assertTrue(compareAttributes(e, vertex));
						}	
						if (!e.getTextNormalize().isEmpty()) {
							assertTrue(compareContent(e, vertex));
						}
					}
				}
			}
*/
			
			graphson = preprocessSTIX.xmlToJson();
			System.out.println(graphson.toString(2));
		//	HashMap<String,Object> result = new ObjectMapper().readValue(graphson, HashMap.class);
		//	for (String key : result.keySet()) 
		//		System.out.println(key + " = " + result.get(key));
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}


	/**
	 * Tests normalize stix: ExploitTarget with Observable and COA
	 */
//	@Test
	public void test_normalizeSTIX_ExploitTarget_with_Observable_COA() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
		try {
			String initialStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Bugtraq-6b79a9f7-b391-4384-9b5d-831ec9572e4e\" " +
				"    timestamp=\"2015-10-19T14:47:07.773Z\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Bugtraq</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:Bugtraq-90dcf3c4-746f-4207-b990-a69b5131cf6e\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability.</et:Description> " +
				"                <et:Short_Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability</et:Short_Description> " +
				"                <et:OSVDB_ID>2222</et:OSVDB_ID> " +
				"                <et:Source>Bugtraq</et:Source> " +
				"                <et:Published_DateTime>2001-01-16T00:00:00.000-05:00</et:Published_DateTime> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable id=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"> " +
				"                            <cybox:Title>Software</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.28\"> " +
				"                                <cybox:Description>SSH Communications Security SSH 1.2.28</cybox:Description> " +
				"                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                                    <ProductObj:Product>SSH Communications Security SSH 1.2.28</ProductObj:Product> " +
				"                                </cybox:Properties> " +
				"                            </cybox:Object> " +
				"                        </stixCommon:Observable> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable id=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"> " +
				"                            <cybox:Title>Software</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.27\"> " +
				"                                <cybox:Description>SSH Communications Security SSH 1.2.27</cybox:Description> " +
				"                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                                    <ProductObj:Product>SSH Communications Security SSH 1.2.27</ProductObj:Product> " +
				"                                </cybox:Properties> " +
				"                            </cybox:Object> " +
				"                        </stixCommon:Observable> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"            <et:Potential_COAs> " +
				"                <et:Potential_COA> " +
				"                    <stixCommon:Course_Of_Action " +
				"                        id=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" xsi:type=\"coa:CourseOfActionType\"> " +
				"                        <coa:Title>Vulnerability</coa:Title> " +
				"                        <coa:Description>Solution: Patches available: SSH Communications Security SSH 1.2.27</coa:Description> " +
				"                        <coa:Information_Source> " +
				"                            <stixCommon:Identity> " +
				"                                <stixCommon:Name>Bugtraq</stixCommon:Name> " +
				"                            </stixCommon:Identity> " +
				"                        </coa:Information_Source> " +
				"                    </stixCommon:Course_Of_Action> " +
				"                </et:Potential_COA> " +
				"            </et:Potential_COAs> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";
			
			String expectedStixString = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Bugtraq-6b79a9f7-b391-4384-9b5d-831ec9572e4e\" " +
				"    timestamp=\"2015-10-19T14:47:07.773Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Bugtraq</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.28\"> " +
				"                <cybox:Description>SSH Communications Security SSH 1.2.28</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>SSH Communications Security SSH 1.2.28</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.27\"> " +
				"                <cybox:Description>SSH Communications Security SSH 1.2.27</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>SSH Communications Security SSH 1.2.27</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:Bugtraq-90dcf3c4-746f-4207-b990-a69b5131cf6e\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability.</et:Description> " +
				"                <et:Short_Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability</et:Short_Description> " +
				"                <et:OSVDB_ID>2222</et:OSVDB_ID> " +
				"                <et:Source>Bugtraq</et:Source> " +
				"                <et:Published_DateTime>2001-01-16T00:00:00.000-05:00</et:Published_DateTime> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"/> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"/> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"            <et:Potential_COAs> " +
				"                <et:Potential_COA> " +
				"                    <stixCommon:Course_Of_Action " +
				"                        idref=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" xsi:type=\"coa:CourseOfActionType\"/> " +
				"                </et:Potential_COA> " +
				"            </et:Potential_COAs> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"    <stix:Courses_Of_Action> " +
				"        <stix:Course_Of_Action " +
				"            id=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"coa:CourseOfActionType\"> " +
				"            <coa:Title>Vulnerability</coa:Title> " +
				"            <coa:Description>Solution: Patches available: SSH Communications Security SSH 1.2.27</coa:Description> " +
				"            <coa:Information_Source> " +
				"                <stixCommon:Identity> " +
				"                    <stixCommon:Name>Bugtraq</stixCommon:Name> " +
				"                </stixCommon:Identity> " +
				"            </coa:Information_Source> " +
				"        </stix:Course_Of_Action> " +
				"    </stix:Courses_Of_Action> " +
				"</stix:STIX_Package> ";
			
			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();
			assertTrue(normalizedStixPackage.validate());
			
			STIXPackage expectedStixPackage = STIXPackage.fromXMLString(expectedStixString);
			assertTrue(normalizedStixPackage.equals(expectedStixPackage));
			
			JSONObject graphson = preprocessSTIX.xmlToGraphson(normalizedStixPackage.toXMLString());
			JSONArray verts = graphson.getJSONArray("vertices");
			Document stixDocument = preprocessSTIX.getSTIXDocument();

			printElement(stixDocument.getRootElement());
			System.out.println(verts.toString(2));

			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile("//*[@id]");							
			List<Element> elementList = new ArrayList<Element>(xp.evaluate(stixDocument));
			for (Element element : elementList) {
				if (parentElementMap.containsKey(element.getName())) {
					System.out.println();
					String id = element.getAttributeValue("id");
					System.out.println("Testing content of " + element.toString() + " with id = " + id);
					JSONObject vertex = null;
					for (int i = 0; i < verts.length(); i++) {
						vertex = verts.getJSONObject(i);
						if (vertex.getString("_id").equals(id)) {
							vertex = verts.getJSONObject(i);
							break;
						}
						vertex = null;
					}
					if (vertex == null)
						System.out.println("null");
					assertNotNull(vertex);
					xp = xpfac.compile(".//*");
					List<Element> eList = new ArrayList<Element>(xp.evaluate(element));
					for (Element e : eList) {
						System.out.println("Working on " + e.toString());
						assertTrue(compareNs(e, vertex));
						if (e.hasAttributes()) {
							assertTrue(compareAttributes(e, vertex));
						}	
						if (!e.getTextNormalize().isEmpty()) {
							assertTrue(compareContent(e, vertex));
						}
					}
				}
			}

			graphson = preprocessSTIX.xmlToJson();
			System.out.println(graphson.toString(2));
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	private boolean compareContent(Element e, JSONObject vertex) {
		System.out.println("Looking for content: " + e.getText());
		String tag = getVertexKey(e);
		String tagContent = tag + "--content";
		for (Object key : vertex.keySet()) {
			String keyString = (String) key;
			String newKey = keyString.replaceFirst("\\d+", "");
			if (tagContent.equals(newKey)) {
				if (e.getTextNormalize().equals(vertex.getString(keyString))) {
					return true;
				}
			}
		}

		return false;
	}

	private boolean compareAttributes(Element e, JSONObject vertex) {
		System.out.println("Looking for attributes: " + e.getAttributes());
		List<Attribute> attrList = e.getAttributes();
		String tag = getVertexKey(e);
		String tagAttr = tag + "--attr";
		for (Object key : vertex.keySet()) {
			String keyString = (String) key;
			String newKey = keyString.replaceFirst("\\d+", "");
			if (tagAttr.equals(newKey)) {
				List<Attribute> vertexAttrList = new ArrayList<Attribute>();
				JSONArray attrArray = vertex.getJSONArray(key.toString());
				for (int i = 0; i < attrArray.length(); i++) {
					JSONObject attrObject = attrArray.getJSONObject(i);
					for (Object key1 : attrObject.keySet()) {
						JSONObject attrContentObject = attrObject.getJSONObject(key1.toString());
						if (attrContentObject.has("ns")) {
							JSONObject attrNsObject = attrContentObject.getJSONObject("ns");
							Set<String> attrSet = attrNsObject.keySet();
							for (String str : attrSet) {
								Namespace attrNS = Namespace.getNamespace(str, attrNsObject.getString(str));
								Attribute newAttribute = new Attribute(key1.toString(), attrContentObject.getString("content"), attrNS);
								vertexAttrList.add(newAttribute);
							}
						} else {
							Attribute newAttribute = new Attribute(key1.toString(), attrContentObject.getString("content"));
							vertexAttrList.add(newAttribute);
						}
					}
				}
				boolean match = true;
				for (Attribute at : vertexAttrList) {
					if (!vertexAttrList.contains(at)) {
						match = false;
					}
				}
				if (match) {
					return true;
				}
			}
		}
		
		return true;
	}

	private String getVertexKey(Element e) {
		String path = XPathHelper.getAbsolutePath(e);
		String[] pathArray = path.split("'");
		String tag = "";
		for (int i = 1; i < pathArray.length; i = i + 4) {
			tag = tag + "--" + pathArray[i];
		}
		
		return tag;
	}

	private boolean compareNs(Element e, JSONObject vertex) {
		System.out.println("Looking for namespace: " + e.getNamespace().toString());
		String tag = getVertexKey(e);
		String tagNs = tag + "--ns";
		Namespace ns = e.getNamespace();
		for (Object key : vertex.keySet()) {
			String keyString = (String) key;
			String newKey = keyString.replaceFirst("\\d+", "");
			if (tagNs.equals(newKey)) {
				JSONObject nsObject = vertex.getJSONObject(keyString);
				if (nsObject.has(ns.getPrefix()) && nsObject.getString(ns.getPrefix()).equals(ns.getURI())) {
					return true;
				} 
			}
		}

		return false;
	}

	/**
	 * Tests stix to graphson with large file ~6KB
	 */
//	@Test
	public void test_flattenStixJson_6KB() {

		System.out.println("alignment.alignment_v2.test_flattenStixJson_6KB()");
		try {

			FileUtils fu = new FileUtils();
			File file = new File("resources/StixDataTest1.xml");
			String initialStixString = fu.readFileToString(file);
			
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();	
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();					
			assertTrue(normalizedStixPackage.validate());
			
			JSONObject graphson = preprocessSTIX.xmlToGraphson(normalizedStixPackage.toXMLString());
			JSONArray verts = graphson.getJSONArray("vertices");
			Document stixDocument = preprocessSTIX.getSTIXDocument();

			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile("//*[@id]");							
			List<Element> elementList = new ArrayList<Element>(xp.evaluate(stixDocument));
			for (Element element : elementList) {
				if (parentElementMap.containsKey(element.getName())) {
					System.out.println();
					System.out.println("Testing content of " + element.toString());
					String id = element.getAttributeValue("id");
					JSONObject vertex = null;
					for (int i = 0; i < verts.length(); i++) {
						vertex = verts.getJSONObject(i);
						if (vertex.getString("_id").equals(id)) {
							vertex = verts.getJSONObject(i);
							break;
						}
						vertex = null;
					}

					assertNotNull(vertex);
				//	printElement(element);
				//	System.out.println(vertex.toString(2));
					xp = xpfac.compile(".//*");
					List<Element> eList = new ArrayList<Element>(xp.evaluate(element));
					for (Element e : eList) {
						System.out.println("Working on " + e.toString());
						assertTrue(compareNs(e, vertex));
						if (e.hasAttributes()) {
							assertTrue(compareAttributes(e, vertex));
						}	
						if (!e.getTextNormalize().isEmpty()) {
							assertTrue(compareContent(e, vertex));
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}	

	/**
	 * Tests stix to graphson with large file ~1.1MB
	 */
//	@Test
	public void test_flattenStixJson_1MB() {

		System.out.println("alignment.alignment_v2.test_flattenStixJson_1MB()");
		try {

			FileUtils fu = new FileUtils();
			File file = new File("resources/StixDataTest2.xml");
			String initialStixString = fu.readFileToString(file);
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();	
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();					
			assertTrue(normalizedStixPackage.validate());
			
			JSONObject graphson = preprocessSTIX.xmlToGraphson(normalizedStixPackage.toXMLString());
			JSONArray verts = graphson.getJSONArray("vertices");
			Document stixDocument = preprocessSTIX.getSTIXDocument();

			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile("//*[@id]");							
			List<Element> elementList = new ArrayList<Element>(xp.evaluate(stixDocument));
			for (Element element : elementList) {
				if (parentElementMap.containsKey(element.getName())) {
					System.out.println();
					System.out.println("Testing content of " + element.toString());
					String id = element.getAttributeValue("id");
					JSONObject vertex = null;
					for (int i = 0; i < verts.length(); i++) {
						vertex = verts.getJSONObject(i);
						if (vertex.getString("_id").equals(id)) {
							vertex = verts.getJSONObject(i);
							break;
						}
						vertex = null;
					}

					assertNotNull(vertex);
				//	printElement(element);
				//	System.out.println(vertex.toString(2));
					xp = xpfac.compile(".//*");
					List<Element> eList = new ArrayList<Element>(xp.evaluate(element));
					for (Element e : eList) {
						System.out.println("Working on " + e.toString());
						assertTrue(compareNs(e, vertex));
						if (e.hasAttributes()) {
							assertTrue(compareAttributes(e, vertex));
						}	
						if (!e.getTextNormalize().isEmpty()) {
							assertTrue(compareContent(e, vertex));
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	/**
	 * Tests stix to graphson with large file ~2.2MB
	 */
//	@Test
	public void test_flattenStixJson_2MB() {

		System.out.println("alignment.alignment_v2.test_flattenStixJson_2MB()");
		try {

			FileUtils fu = new FileUtils();
			File file = new File("resources/StixDataTest3.xml");
			String initialStixString = fu.readFileToString(file);
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();	
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();					
			assertTrue(normalizedStixPackage.validate());
			
			JSONObject graphson = preprocessSTIX.xmlToGraphson(normalizedStixPackage.toXMLString());
			JSONArray verts = graphson.getJSONArray("vertices");
			Document stixDocument = preprocessSTIX.getSTIXDocument();

			XPathFactory xpfac = XPathFactory.instance();
			XPathExpression xp = xpfac.compile("//*[@id]");							
			List<Element> elementList = new ArrayList<Element>(xp.evaluate(stixDocument));
			for (Element element : elementList) {
				if (parentElementMap.containsKey(element.getName())) {
					System.out.println();
					System.out.println("Testing content of " + element.toString());
					String id = element.getAttributeValue("id");
					JSONObject vertex = null;
					for (int i = 0; i < verts.length(); i++) {
						vertex = verts.getJSONObject(i);
						if (vertex.getString("_id").equals(id)) {
							vertex = verts.getJSONObject(i);
							break;
						}
						vertex = null;
					}

					assertNotNull(vertex);
				//	printElement(element);
				//	System.out.println(vertex.toString(2));
					xp = xpfac.compile(".//*");
					List<Element> eList = new ArrayList<Element>(xp.evaluate(element));
					for (Element e : eList) {
						System.out.println("Working on " + e.toString());
						assertTrue(compareNs(e, vertex));
						if (e.hasAttributes()) {
							assertTrue(compareAttributes(e, vertex));
						}	
						if (!e.getTextNormalize().isEmpty()) {
							assertTrue(compareContent(e, vertex));
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}



