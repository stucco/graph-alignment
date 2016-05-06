package gov.ornl.stucco.alignment;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;
import java.util.Iterator;

import org.json.JSONObject;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Document;
import org.jdom2.Element; 
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;
 
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;  

/**
 * Splitting nested CybOX objects into separate Observables.
 *
 * @author Maria Vincent
 */

abstract class PreprocessCybox {

	public static String print(Element e) {
		XMLOutputter xmlOutputter = new XMLOutputter(Format.getPrettyFormat());
		System.out.println(xmlOutputter.outputString(e));

		return xmlOutputter.outputString(e);
	}

	public static Map<String, Element> normalizeCybox(Element element) {	
		Map<String, Element> normalizedElements = new HashMap<String, Element>();
		List<Element> propertiesList = findProperties(element);	
    Iterator<Element> iterator = propertiesList.iterator();
    while (iterator.hasNext()) {

    	Element properties = iterator.next();
    	String parentName = properties.getParentElement().getName();
    	if (properties.getAttribute("object_reference") != null) {
    		continue;
    	} 
    	if (!parentName.equals("Object")) {
    		iterator.remove();
    		String type = properties.getAttributeValue("type", Namespace.getNamespace("http://www.w3.org/2001/XMLSchema-instance")).split(":")[1];
    		Element observable = buildNewObservable(properties.removeContent(), type, ConfigFileLoader.cyboxObjects.getJSONObject(type));
    		String id = observable.getAttributeValue("id");
    		properties.setAttribute(new Attribute("object_reference", id));
    		properties.addNamespaceDeclaration(observable.getNamespace("stucco"));
    		Element newObject = observable.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
    		Element newProperties = newObject.getChild("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
    		normalizedElements.putAll(normalizeProperties(newProperties));
    		normalizedElements.put(id, observable);
    	} else {
    		normalizedElements.putAll(normalizeProperties(properties));	
    	}
    }

    return normalizedElements;
	}

	private static List<Element> findProperties(Element element) {
		List<Element> list = new ArrayList<Element>();
		String name = element.getName();
		if (name.equals("Properties")) {
			if (element.getAttribute("object_reference") == null) {
				list.add(element);
			}
		} else {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				list.addAll(findProperties(child));
			}
		}
		return list;
	}

	/* 
	 *	extracting Address, IP, Port, DNSRecord, etc, making them self sustain objects, and adding referensing id 
	 */
	private static Map<String, Element> normalizeProperties(Element properties) {
		Map<String, Element> normalizedElements = new HashMap<String, Element>();
		String type = properties.getAttributeValue("type", Namespace.getNamespace("http://www.w3.org/2001/XMLSchema-instance")).split(":")[1];
		JSONObject cyboxType = ConfigFileLoader.cyboxObjects.getJSONObject(type);
		List<Element> children = properties.getChildren();
		Iterator<Element> iterator = children.iterator();
		while (iterator.hasNext()) {
			Element child = iterator.next();
			String propertyType = getPropertyType(child.getName(), cyboxType);
			if (ConfigFileLoader.cyboxObjects.has(propertyType)) {
				normalizedElements.putAll(traverseProperties(child, propertyType, ConfigFileLoader.cyboxObjects.getJSONObject(propertyType)));
			}
		}
		return normalizedElements;
	}

	private static Map<String, Element> traverseProperties(Element element, String type, JSONObject cyboxType) {
		Map<String, Element> newObservables = new HashMap<String, Element>();
		if (cyboxType.has("objectReference")) {
			if (element.getAttribute("object_reference") == null) {
				Element observable = buildNewObservable(element.removeContent(), type, cyboxType);
				element.setAttribute("object_reference", observable.getAttributeValue("id"));
				element.addNamespaceDeclaration(observable.getNamespace("stucco"));
				newObservables.put(observable.getAttributeValue("id"), observable);
				newObservables.putAll(normalizeCybox(observable));
				
				return newObservables;
			}
		} else {
			List<Element> children = element.getChildren();
			for (Element child : children) {
				String name = child.getName();
				String propertyType = getPropertyType(name, cyboxType);
				if (ConfigFileLoader.cyboxObjects.has(propertyType))
					newObservables.putAll(traverseProperties(child, propertyType, ConfigFileLoader.cyboxObjects.getJSONObject(propertyType)));
			}
		}
		return newObservables;
	}

	private static String getPropertyType(String propertyName, JSONObject cyboxType) {
		JSONObject elements = cyboxType.optJSONObject("elements");
		if (elements != null) {
			if (elements.has(propertyName)) {
				String childType = elements.getJSONObject(propertyName).getString("type");
				return (childType.isEmpty()) ? null : childType;
			}
		} 
		String base = cyboxType.getString("base");
		JSONObject baseObject = ConfigFileLoader.cyboxObjects.optJSONObject(base);
		if (baseObject != null) {
			elements = baseObject.optJSONObject("elements");
			if (elements != null) {
				JSONObject childType = elements.optJSONObject(propertyName);
				return (childType == null) ? null : childType.getString("type");
			}
		}

		return null;
	}

	private static Element buildNewObservable(List<Content> content, String type, JSONObject cyboxType) {
		Element observable = new Element("Observable", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		observable.setAttribute(new Attribute("id", "stucco:Observable-" + UUID.randomUUID().toString()));
		observable.addNamespaceDeclaration(Namespace.getNamespace("stucco", "gov.ornl.stucco"));
		Element object = new Element("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		observable.setContent(object);
		Element properties = new Element("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		object.setContent(properties);
		String typeValue = cyboxType.getString("prefix") + ":" + type;
		properties.setAttribute(new Attribute("type", typeValue, Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")));
		properties.addNamespaceDeclaration(Namespace.getNamespace(cyboxType.getString("prefix"), cyboxType.getString("URI")));
		properties.setContent(content);

		return observable;
	}
}









