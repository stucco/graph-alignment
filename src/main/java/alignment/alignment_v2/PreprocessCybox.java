package alignment.alignment_v2;

import javax.xml.namespace.QName;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

abstract class PreprocessCybox {

	private static final Map<String, String> typeMap;
	private static final Map<String, String> nsMap;
	private static final Map<String, Set<String>> stuccoNsMap;
	private static final Set<String> referencingElements;

	static {
		Map<String, Set<String>> objectMap = new HashMap<String, Set<String>>();
		Set<String> objectSet = new HashSet<String>();
		objectSet.add("AccountObj");
		objectSet.add("UserAccountObj");
		objectMap.put("UserAccountObj", Collections.unmodifiableSet(objectSet));
		objectSet = new HashSet<String>();
		objectSet.add("AddressObj");
		objectSet.add("PacketObj");
		objectSet.add("NetFlowObj");
		objectSet.add("SocketAddressObj");
		objectSet.add("PortObj");
		objectMap.put("NetFlowObj", Collections.unmodifiableSet(objectSet));
		objectSet = new HashSet<String>();
		objectSet.add("ASObj");
		objectMap.put("ASObj", Collections.unmodifiableSet(objectSet));
		objectSet = new HashSet<String>();
		objectSet.add("AddressObj");
		objectSet.add("HTTPSessionObj");
		objectSet.add("URIObj");
		objectSet.add("PortObj");
		objectMap.put("HTTPSessionObj", Collections.unmodifiableSet(objectSet));
		objectSet = new HashSet<String>();
    objectSet.add("ProductObj");
    objectMap.put("ProductObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("AddressObj");
    objectSet.add("SocketAddressObj");
    objectSet.add("PortObj");
    objectMap.put("SocketAddressObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("AddressObj");
    objectSet.add("DNSRecordObj");
    objectSet.add("URIObj");
    objectMap.put("DNSRecordObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("AddressObj");
    objectMap.put("AddressObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("HostnameObj");
    objectMap.put("HostnameObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("DomainNameObj");
    objectMap.put("DomainNameObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("WhoisObj");
    objectSet.add("AddressObj");
    objectSet.add("URIObj");
    objectMap.put("WhoisObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("PortObj");
    objectMap.put("PortObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
    objectSet.add("ProcessObj");
    objectSet.add("NetworkConnectionObj");
    objectSet.add("AddressObj");
    objectSet.add("DNSRecordObj");
    objectSet.add("SocketAddressObj");
    objectSet.add("DNSQueryObj");
    objectSet.add("HTTPSessionObj");
    objectSet.add("URIObj");
    objectSet.add("PortObj");
    objectMap.put("ProcessObj", Collections.unmodifiableSet(objectSet));
    objectSet = new HashSet<String>();
		stuccoNsMap = Collections.unmodifiableMap(objectMap);

		/* object namespace mapped to its required type attribute */
		Map<String, String> map = new HashMap<String, String>();
		map.put("UserAccountObj", "UserAccountObj:UserAccountObjectType");
		map.put("NetFlowObj", "NetFlowObj:NetworkFlowObjectType");
		map.put("ASObj", "ASObj:ASObjectType");
		map.put("HTTPSessionObj","HTTPSessionObj:HTTPSessionObjectType");
		map.put("ProductObj", "ProductObj:ProductObjectType");
		map.put("SocketAddressObj", "SocketAddressObj:SocketAddressObjectType");
		map.put("DNSRecordObj", "DNSRecordObj:DNSRecordObjectType");
		map.put("AddressObj", "AddressObj:AddressObjectType");
		map.put("HostnameObj", "HostnameObj:HostnameObjectType");
		map.put("DomainNameObj", "DomainNameObj:DomainNameObjectType");
		map.put("WhoisObj", "WhoisObj:WhoisObjectType");
		map.put("PortObj", "PortObj:PortObjectType");
		map.put("ProcessObj", "ProcessObj:ProcessObjectType"); 
		map.put("URIObj", "URIObj:URIObjectType");
		typeMap = Collections.unmodifiableMap(map);

		map = new HashMap<String, String>();
		map.put("UserAccountObj", "http://cybox.mitre.org/objects#UserAccountObject-2");
		map.put("NetFlowObj", "http://cybox.mitre.org/objects#NetworkFlowObject-2");
		map.put("ASObj", "http://cybox.mitre.org/objects#ASObject-1");
		map.put("HTTPSessionObj","http://cybox.mitre.org/objects#HTTPSessionObject-2");
		map.put("ProductObj", "http://cybox.mitre.org/objects#ProductObject-2");
		map.put("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1");
		map.put("DNSRecordObj", "http://cybox.mitre.org/objects#DNSRecordObject-2");
		map.put("AddressObj", "http://cybox.mitre.org/objects#AddressObject-2");
		map.put("HostnameObj", "http://cybox.mitre.org/objects#HostnameObject-1");
		map.put("DomainNameObj", "http://cybox.mitre.org/objects#DomainNameObject-1");
		map.put("WhoisObj", "http://cybox.mitre.org/objects#WhoisObject-2");
		map.put("PortObj", "http://cybox.mitre.org/objects#PortObject-2");
		map.put("ProcessObj", "http://cybox.mitre.org/objects#ProcessObject-2");
		map.put("URIObj", "http://cybox.mitre.org/objects#URIObject-2"); 
		nsMap = Collections.unmodifiableMap(map);

		Set<String> set = new HashSet<String>();
		set.add("SocketAddressObj:IP_Address");
		set.add("SocketAddressObj:Port");
		set.add("DNSRecordObj:Domain_Name");
		set.add("DNSRecordObj:IP_Address");
		set.add("NetFlowObj:Src_Socket_Address");
		set.add("NetFlowObj:Dest_Socket_Address");
		set.add("HTTPSessionObj:Domain_Name");
		set.add("HTTPSessionObj:Port");
		set.add("HTTPSessionObj:From");
		set.add("ProcessObj:Port");
		referencingElements = Collections.unmodifiableSet(set);
	}

	private static String print(Element e) {
		XMLOutputter xmlOutputter = new XMLOutputter(Format.getPrettyFormat());
    System.out.println(xmlOutputter.outputString(e));
    
    return xmlOutputter.outputString(e);
	}

	public static Map<String, Element> normalizeCybox(Element element) {
		if (!element.getName().equals("Observable")) {
			return null;
		}
		Map<String, Element> normalizedElements = new HashMap<String, Element>();
		String type = getObjectType(element);
		Map<Element, List<Element>> stuccoObjectsMap = extractStuccoObjects(element, type);
		for (Element parentObject : stuccoObjectsMap.keySet()) {
			List<Element> list = stuccoObjectsMap.get(parentObject);
			for (Element stuccoObject : list) {
				addNewRelation(parentObject, stuccoObject);
				normalizedElements.put(stuccoObject.getAttributeValue("id"), stuccoObject);
			}
		}

		return normalizedElements;
	}

	private static String getObjectType(Element element) {
		Element object = element.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		if (object == null) {
			return null;
		}
		Element properties = object.getChild("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		if (properties == null) {
			return null;
		}
		String type = properties.getAttributeValue("type", Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")).split(":")[0];

		return type;
	}

	private static Map<Element, List<Element>> extractStuccoObjects(Element element, String type) {
		Map<Element, List<Element>> map = new HashMap<Element, List<Element>>();
		List<Element> children = element.getChildren();
		for (Element child : children) {
			String prefix = child.getNamespacePrefix();
			if (nsMap.containsKey(prefix) && !prefix.equals(type)) {
				Element newElement = buildStuccoObject(element, prefix);
				List<Element> list = (map.containsKey(element)) ? map.get(element) : new ArrayList<Element>();
				list.add(newElement);
				map.put(element, list);
				map.putAll(extractStuccoObjects(newElement, prefix));

				return map;
			} else {
				map.putAll(extractStuccoObjects(child, type));
			}
		}

		return map;
	}

	private static String getPath(Element element) {
		Element parent = element.getParentElement();
		String parentName = parent.getName();
		Element grandParent = parent.getParentElement();
		String grandParentName = grandParent.getName();
		Element grandGrandParent = grandParent.getParentElement();
		String grandGrandParentName = grandGrandParent.getName();

		return grandGrandParentName + "/" + grandParentName + "/" + parentName;
	}

	private static Element buildStuccoObject(Element element, String ns) {
	//	print(element);
		String type = typeMap.get(ns);
		Element properties = new Element("Properties",  Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		properties.setAttribute("type", type, Namespace.getNamespace("xsi", "http://www.w3.org/2001/XMLSchema-instance"));
		properties.addNamespaceDeclaration(Namespace.getNamespace(ns, nsMap.get(ns)));
		Element object = new Element("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		object.addContent(properties);
		Element observable = new Element("Observable", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
		observable.setAttribute( new Attribute("id", "Observable-" + UUID.randomUUID().toString()));
		observable.addContent(object);
		Set<String> prefixSet = stuccoNsMap.get(ns);
		if (prefixSet == null) {
			prefixSet = new HashSet<String>();
			prefixSet.add(ns);
		}
		List<Element> children = element.getChildren();
		for (Element child : children) {
			String prefix = child.getNamespacePrefix();
			if (prefixSet.contains(prefix)) {
				properties.addContent(child.clone().detach());
			} 
		}

		return observable;
	}

	private static void addNewRelation(Element element, Element newElement) {
		String name = element.getQualifiedName();
		if (referencingElements.contains(name)) {
			Attribute id = newElement.getAttribute("id");
			if (element.getAttribute("id") != null) {
				element.removeAttribute("id");
			}
			element.removeContent();
			element.setAttribute("object_reference", id.getValue());
		} else {
			Element parent = element;
			name = element.getName();
			while (name != "Properties") {
				parent = parent.getParentElement();
				name = parent.getName();
			}
			Element relatedObjects = parent.getParentElement().getChild("Related_Objects", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			if (relatedObjects == null) {
				relatedObjects = new Element("Related_Objects", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
				parent.getParentElement().addContent(relatedObjects);
			}
			Element relatedObject = new Element("Related_Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			relatedObject.setAttribute("idref", newElement.getAttributeValue("id"));
			relatedObjects.addContent(relatedObject);
		}
	}
}








