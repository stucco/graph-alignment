package alignment.alignment_v2;

import javax.xml.namespace.QName;
import org.xml.sax.SAXException;

import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;

import java.io.StringReader;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

import org.mitre.stix.stix_1.STIXPackage;

public class PreprocessSTIXwithJDOM2 {

	private Document stixDoc = null;
	private static final Namespace stixNS = Namespace.getNamespace("stix", "http://stix.mitre.org/stix-1");
	private static final Map<String, Integer> comparisonMap;
	private static final Map<String, String> elementParentMap;
	private static final Map<String, Element> stixElementMap;
	static {
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
		elementParentMap = Collections.unmodifiableMap(map);
					
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
		comparisonMap = Collections.unmodifiableMap(enumMap);
	}

	private class STIXComparator implements Comparator<Element> {
		public int compare(Element e1, Element e2) {
			return comparisonMap.get(e1.getQualifiedName()).compareTo(comparisonMap.get(e2.getQualifiedName()));
		}	
	}

	public STIXPackage getSTIXPackage() {
		XMLOutputter out = new XMLOutputter(Format.getPrettyFormat());
		return STIXPackage.fromXMLString(out.outputString(stixDoc));
	}

	public Document getSTIXDocument() {
		return stixDoc;
	}

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
	
	private void print(String stix) {
		STIXPackage testPackage = STIXPackage.fromXMLString(stix);
		System.out.println(testPackage.toXMLString(true));
	}

	public void normalizeSTIXPackage(String stixString) {
		stixDoc = parseXMLText(stixString);
		Element rootElement = stixDoc.getRootElement();
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


	private void normalizeSTIXHelper(Element rootElement, String name, List<Element> elementList) {
		Element parentElement = null;
		if (rootElement.getChild(elementParentMap.get(name), stixNS) == null) {
			parentElement = new Element(elementParentMap.get(name), stixNS);
			rootElement.addContent(parentElement);
		} else {
			parentElement = rootElement.getChild(elementParentMap.get(name), stixNS);
		}

		for (Element element : elementList) {
			parentElement.addContent(element);
		}
	}
		
	private HashMap traverseSTIXElements(Element element, HashMap<String, List<Element>> elementMap) {
		List children = element.getChildren();
		Iterator it = children.iterator();
		while (it.hasNext()) {
			Element child = (Element) it.next();
			String name = child.getName();
			if (stixElementMap.containsKey(name) && !child.getNamespace().equals(stixElementMap.get(name).getNamespace()) && child.getAttribute("idref") == null) {
				Attribute id = null;
				if (child.getAttribute("id") != null) {
					id = child.getAttribute("id");
					child.removeAttribute("id");
				} else {
					id = new Attribute("id", name + "-" + UUID.randomUUID().toString()); 
				}

				List<Element> elementList = (elementMap.containsKey(name)) ? elementMap.get(name) : new ArrayList<Element>();
				Element newElement = setSTIXElement(stixElementMap.get(name).clone(), id, child);
				elementList.add(newElement);
				elementMap.put(name, elementList);

				child.setAttribute(new Attribute("idref", id.getValue()));
				child.removeContent();

				traverseSTIXElements(newElement, elementMap);
			}
			traverseSTIXElements(child, elementMap);	
		}
		return elementMap;
	}

	private Element setSTIXElement(Element element, Attribute id, Element initElement) {
		element.setAttribute(id);
		element.setContent(initElement.cloneContent());

		List<Attribute> attrList = initElement.getAttributes();
		for (Attribute attr : attrList) {
			element.setAttribute(attr.clone());
		}

		return element;
	}	

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

