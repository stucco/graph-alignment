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
import java.util.Iterator;

import java.io.StringReader;  
import java.io.IOException;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PreprocessSTIX {

	private static final Logger logger = LoggerFactory.getLogger(PreprocessSTIX.class);

	private static final Namespace xsiNS = Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance");
	private static final Map<String, Namespace> stixElementMap;
	private static final Set<String> stixParentElementSet;

/**
 * Normalizing STIX packges by removing nested elements.
 *
 * @author Maria Vincent
 */

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

	/*
	 *	Parses xml String and converts it to jdom2 Document
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

	/*
	 *	Normalizes (refactors) stix core elements (Observable, Indicator, COA, etc ...) 
	 *	by cloning content, appending it to the proper parent element, and adding reference to it from its original location
	 */
	public Map<String, Element> normalizeSTIX(String stixString) {
		Map<String, Element> stixElements = new HashMap<String, Element>();
		/* wrapping entire doc into one common root 
		to avoid exception when there is a list of packages one after another */
		stixString = stixString.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
		stixString = "<root>" + stixString + "</root>";
		Document document = parseXMLText(stixString);
		if (document == null) {
			return null;
		}
		List<Element> packageList = document.getRootElement().getChildren(); 
		Iterator<Element> packageIterator = packageList.iterator();
		while(packageIterator.hasNext()) {
			Element pack = packageIterator.next();
			Map<String, Element> map = normalizeSTIXPackage(pack);
			stixElements.putAll(map);
			packageIterator.remove();
		}

		return stixElements;
	}

	private Map<String, Element> normalizeSTIXPackage(Element stixPackage) {
		/* constructing a map of namespaces (prefix mapped to uri); 
		   jdom does not extract all the namespaces required by element, so we need to do it manually */
		Map<String, String> namespaceMap = new HashMap<String, String>();
		List<Namespace> namespaceList = stixPackage.getNamespacesIntroduced();
		for (Namespace namespace : namespaceList) {
			namespaceMap.put(namespace.getPrefix(), namespace.getURI());
		}
		Map<String, Element> stixElements = new HashMap<String, Element>();
		/* looking for the elements that should be referenced and storing them in stixElements map */
		List<Element> outerElementList = stixPackage.getChildren();
		Iterator<Element> outerElementIterator = outerElementList.iterator();
		while (outerElementIterator.hasNext()) {
			Element outerElement = outerElementIterator.next();
			/* if it is STIX_Header or STIX_RelatedPackages, then we do not need to warry about them;
				 we only keep Observables, Indicators, etc .. */
			if (stixParentElementSet.contains(outerElement.getQualifiedName())) { 
				/* this round extracts Observable from Observables and etc. */
				List<Element> elementList = outerElement.getChildren();
				Iterator<Element> elementListIterator = elementList.iterator();
				while (elementListIterator.hasNext()) {
					Element element = elementListIterator.next();
					//TODO: add mover vertex types, such as Kill_Chain, Pools ...
					if (!stixElementMap.containsKey(element.getName())) {
						continue;
					}
					elementListIterator.remove();
					/* now we need to normalize namespaces of extracted elements, 
					   and travers their children to pull out imbeded Observables, COAs, etc.. */
					normalizeNamespaces(element, namespaceMap);
					String id = getElementId(element);
					List<Element> contentList  = element.getChildren();
					for (Element content : contentList) {
						Map<String, Element> map = traverseSTIXElements(content, namespaceMap);
						stixElements.putAll(map);
					}
					element.setNamespace(stixElementMap.get(element.getName()));
					stixElements.put(id, element);
				}
			}
			outerElementIterator.remove();
		}
		
		stixElements.putAll(preprocessObservableTtpEt(stixElements));

		return stixElements;
	}				

	private String getElementId(Element element) {
		Attribute id = null;
		if ((id = element.getAttribute("id")) == null) {
			id = new Attribute("id", "stucco:" + element.getName() + "-" + UUID.randomUUID().toString());
			element.addNamespaceDeclaration(Namespace.getNamespace("stucco", "gov.ornl.stucco"));
			element.setAttribute(id);
		}

		return id.getValue();
	}

	/* 
	 *	Traverses stix elements to find the one that should be moved out and referenced
	 */	
	private Map<String, Element> traverseSTIXElements(Element element, Map<String, String> namespaceMap) {
		normalizeNamespaces(element, namespaceMap);
		Map<String, Element> stixElements = new HashMap<String, Element>();
		String name = element.getName();
		if (stixElementMap.containsKey(name) && element.getAttribute("idref") == null && 
			(name.equals("Observable") || element.getAttribute("type", xsiNS) != null)) {
			Element newElement = setNewElement(element);
			stixElements.put(newElement.getAttributeValue("id"), newElement);
			List<Element> children = newElement.getChildren();
			for (Element child : children) {
				stixElements.putAll(traverseSTIXElements(child, namespaceMap));
			}
		} else {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				stixElements.putAll(traverseSTIXElements(child, namespaceMap));
			}
		}

		return stixElements;
	}

	/*
	 *	Copies the content of element into newElement, removing content, and adding idref instead 
	 */
	private Element setNewElement(Element element) {
		String name = element.getName();
		if (element.getAttribute("id") == null) {
			element.setAttribute(new Attribute("id", name + "-" + UUID.randomUUID().toString()));
		}
		Element newElement = element.clone().detach();
		newElement.setNamespace(stixElementMap.get(name));
		element.removeContent();
		Attribute id = element.getAttribute("id");
		id.setName("idref");

		return newElement;
	}

	/* 
	 *	in stix values of attributes may also have namespaces, but jdom does not know how to work with them,
	 *	so we need to check every attribute value for prefix, and add namespace if prefix is present 
	 */
	private void normalizeNamespaces(Element element, Map<String, String> namespaceMap) {
		List<Namespace> namespaceList = element.getNamespacesIntroduced();
		for (Namespace namespace : namespaceList) {
			namespaceMap.put(namespace.getPrefix(), namespace.getURI());
		}
		List<Attribute> attrList = element.getAttributes();
		for (Attribute attr : attrList) {
			String value = attr.getValue();
			if (value.contains(":")) {
				String prefix = value.split(":")[0];
				if (namespaceMap.containsKey(prefix)) {
					element.addNamespaceDeclaration(Namespace.getNamespace(prefix, namespaceMap.get(prefix)));
				}
			}
		}
	}

	/*
	 *	Preprocessing Observable, such as splitting IP, Port, URL, etc form the same object
	 *	Preprocessing TTP, such as splitting list of Malware or Exploits from single TTP
	 *	Preprocessing Exploit Target, such as splitting list of Vulnerabilities from single Exploit Target
	 */
	private Map<String, Element> preprocessObservableTtpEt(Map<String, Element> stixElements) {
		Map<String, Element> map = new HashMap<String, Element>();
		for (Map.Entry<String, Element> entry : stixElements.entrySet()) {
			Element element = entry.getValue();
			String name = element.getName();
			/* now we are looking for Observables to normalize them,
		   such as extract IP, Port, etc.. from fields of other objects descriptions */
			if (name.equals("Observable")) {
				Map<String, Element> preprocessedObservable = PreprocessCybox.normalizeCybox(element);
				if (preprocessedObservable != null) {
					map.putAll(preprocessedObservable);
				}
			/* checking if TTP contains multiple malware or exploits; if so, replicating it */
			} else if (name.equals("TTP")) {
				Map<String, Element> preprocessedTTP = PreprocessTTP.normalizeTTP(element);
				if (preprocessedTTP != null) {
					map.putAll(preprocessedTTP);
				}
			/* checking if Exploit Target contains multiple Vulnerabilities; if so, replicating it */
			} else if (name.equals("Exploit_Target")) {
				Map<String, Element> preprocessedET = PreprocessExploitTarget.normalizeET(element);
				if (preprocessedET != null) {
					map.putAll(preprocessedET);
				}
			}
		}

		return map;
	}
}