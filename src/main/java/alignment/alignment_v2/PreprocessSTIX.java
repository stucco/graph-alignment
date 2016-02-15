package alignment.alignment_v2;

import javax.xml.namespace.QName;
import org.xml.sax.SAXException;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

import java.io.StringReader;
import java.io.IOException;

import org.jdom2.output.XMLOutputter;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;

import org.mitre.stix.stix_1.STIXPackage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PreprocessSTIX {

	private static final Logger logger = LoggerFactory.getLogger(PreprocessSTIX.class);

	private static final Namespace xsiNS = Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
	private static final Map<String, Namespace> stixElementMap;
	private static final Set<String> stixParentElementSet;

	static {
		/* stix elements wrapers */
		Set<String> set = new HashSet<String>();
		set.add("stix:Observables");
		set.add("stix:Indicators");
		set.add("stix:TTPs");
		set.add("stix:Exploit_Targets");
		set.add("stix:Incidents");
		set.add("stix:Courses_Of_Action");
		set.add("stix:Campaigns");
		set.add("stix:Threat_Actors");
		stixParentElementSet = Collections.unmodifiableSet(set);

		Map<String, Namespace> map = new HashMap<String, Namespace>();
		map.put("Observable", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		map.put("Exploit_Target", Namespace.getNamespace("et", "http://stix.mitre.org/ExploitTarget-1"));
		map.put("Course_Of_Action", Namespace.getNamespace("coa", "http://stix.mitre.org/CourseOfAction-1"));
		map.put("Indicator", Namespace.getNamespace("indicator", "http://stix.mitre.org/Indicator-2"));
		map.put("TTP", Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1"));
		map.put("Incident", Namespace.getNamespace("incident", "http://stix.mitre.org/Incident-1"));
		map.put("Campaign", Namespace.getNamespace("campaign", "http://stix.mitre.org/Campaign-1"));
		map.put("Threat_Actor", Namespace.getNamespace("ta", "http://stix.mitre.org/ThreatActor-1"));
		stixElementMap = Collections.unmodifiableMap(map);
	}

	/**
	 * Parses xml String and converts it to jdom2 Document
	*/ 
	public static Document parseXMLText(String documentText) {
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
	* Normalizes (refactors) stix core elements (Observable, Indicator, COA, etc ...) 
	* by cloning content, appending it to the proper parent element, and adding reference to it from its original location
	* @param stixString stix package of type String
	*/
	public Map<String, Element> normalizeSTIX(String stixString) {
		stixString = stixString.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
		stixString = "<root>" + stixString + "</root>";
		Document document = parseXMLText(stixString);
		Map<String, Element> stixElements = new HashMap<String, Element>();
		List<Element> packageList = getSTIXPackages(document.getRootElement(), new ArrayList<Element>());
		for (Element pack : packageList) {
			normalizeSTIXPackage(pack, stixElements);
		}

		return stixElements;
	}

	/* sometimes document consists of multiple STIX_Packages, so we neet to extract them */
	private List<Element> getSTIXPackages(Element element, List<Element> packageList) {
		List<Element> childList = element.getChildren();
		for (Element child : childList) {
			String name = child.getName();
			if (name.equals("STIX_Package")) {
				packageList.add(child);
			} 
			else {
				getSTIXPackages(child, packageList);
			}
		}
		return packageList;
	}

	private void normalizeSTIXPackage(Element stixPackage, Map<String, Element> stixElements) {
		/* constructing a map of namespaces (prefix mapped to uri); 
		   jdom does not extract all the namespaces required by element, so we need to do it manually */
		Map<String, String> nsMap = getNamespaceMap(stixPackage, new HashMap<String, String>());

		/* looking for the elements that should be referenced and storing them in stixElements map */
		traverseSTIXElements(stixPackage, stixElements);

		/* manually checking for missing namespaces */
		for (String key : stixElements.keySet()) {
			Element element = stixElements.get(key);
			normalizeNamespaces(element, nsMap);
		}

		List<Element> children = stixPackage.getChildren(); 
		for (Element child : children) {
			String name = child.getQualifiedName();
			if (stixParentElementSet.contains(name)) {
				List<Element> elementList = child.getChildren();
				for (Element element : elementList) {
					element.setNamespace(stixElementMap.get(element.getName()));
					normalizeNamespaces(element, nsMap);
					String id = element.getAttributeValue("id");
					stixElements.put(id, element.clone());
				}
			}
		}

		stixPackage.removeContent();
	}				

	private void removeUnwantedElements(Element stixPackage) {
		List<Element>children = stixPackage.getChildren();
		for (Element child : children) {
			String name = child.getQualifiedName();
			if (!stixParentElementSet.contains(name)) {
				stixPackage.removeChild(child.getName(), child.getNamespace());
			}
		}
	}
	
	/** 
	* Traverses stix elements to find the one that should be moved out and referenced
	* @param element the element that will be traversed
	* @param stixElements contains found elements that should be referenced
	*/	
	private void traverseSTIXElements(Element element, Map<String, Element> stixElements) {
		if (stixParentElementSet.contains(element.getQualifiedName())) {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				if (child.getAttribute("id") == null) {
					child.setAttribute(new Attribute("id", child.getName() + "-" + UUID.randomUUID().toString()));
				}
				List<Element> grandChildrenList = child.getChildren();
				for (Element grandChild : grandChildrenList) {
					traverseSTIXElements(grandChild, stixElements);
				}
			}
		} else {
			String name = element.getName();
			if (stixElementMap.containsKey(name) && element.getAttribute("idref") == null) {	
				if (name.equals("Observable") || element.getAttribute("type", xsiNS) != null) {
					Element newElement = setNewElement(element);
					String id = newElement.getAttributeValue("id");
					stixElements.put(id, newElement);
					List<Element> children = newElement.getChildren();
					for (Element child : children) {
						traverseSTIXElements(child, stixElements);
					}
				}
			}
			List<Element> children = element.getChildren();
			for (Element child : children) {
				traverseSTIXElements(child, stixElements);	
			}
		}
	}

	/**
	 * Copies the content of element into newElement, removing content, and adding idref instead 
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
		newElement.setNamespace(stixElementMap.get(newElement.getName()));
		newElement.setAttribute(id);
		element.setAttribute(new Attribute("idref", id.getValue()));
		element.removeContent();
		
		return newElement;
	}

	private Map<String, String> getNamespaceMap(Element element, Map<String,String> map) {
		List<Namespace> nsList = element.getNamespacesIntroduced();
		for (Namespace ns : nsList) {
			String prefix = ns.getPrefix();
			String uri = ns.getURI();
			if (!prefix.isEmpty() && !uri.isEmpty()) {
				map.put(ns.getPrefix(), ns.getURI());
			}
		}
	
		List<Element> children = element.getChildren();
		for (Element child : children) {
			getNamespaceMap(child, map);
		}
		return map;
	}

	private void normalizeNamespaces(Element element, Map<String, String> nsMap) {
		List<Attribute> attrList = element.getAttributes();
		for (Attribute attr : attrList) {
			String[] value = attr.getValue().split(":");
			if (value.length == 2) {
				String prefix = value[0];
				if (nsMap.containsKey(prefix)) {
					element.addNamespaceDeclaration(Namespace.getNamespace(prefix, nsMap.get(prefix)));
				}
			}
		}
		List<Element> children = element.getChildren();
		for (Element child : children) {
			normalizeNamespaces(child, nsMap);
		}
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