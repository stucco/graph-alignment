package gov.ornl.stucco.alignment;

import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;
import java.util.Iterator;

import java.io.Serializable;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Splitting a list of Malware or Exploits from one TTP to multiple related TTPs.
 *
 * @author Maria Vincent
 */

abstract class PreprocessTTP {

	private static final Logger logger = LoggerFactory.getLogger(PreprocessTTP.class);

	private static final Namespace ttpNS = Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1");
	private static final Namespace stuccoNS = Namespace.getNamespace("stucco", "gov.ornl.stucco");
	private static final Namespace stixCommonNS = Namespace.getNamespace("stixCommon", "http://stix.mitre.org/common-1");
	private static final Map<String, Integer> propOrder;

	static {
		Map<String, Integer> map = new HashMap<String, Integer>();
		map.put("Title", 0);
		map.put("Description", 1);
		map.put("Short_Description", 2); 
		map.put("Intended_Effects", 3);
		map.put("Behavior", 4);
		map.put("Resources", 5);
		map.put("Victim_Targeting", 6); 
		map.put("Exploit_Targets", 7);
		map.put("Related_TTPs", 8);
		map.put("Kill_Chain_Phases", 9);
		map.put("Information_Source", 10);
		map.put("Kill_Chains", 11);
		map.put("Handling", 12);
		map.put("Related_Packages", 13);
		propOrder = Collections.unmodifiableMap(map);
	}

	private static class TTPComparator implements Comparator<Element>, Serializable {
		public int compare(Element e1, Element e2) {
			return propOrder.get(e1.getName()).compareTo(propOrder.get(e2.getName()));
		}	
	}

	public static Map<String, Element> normalizeTTP(Element ttp) {
		Element behavior = ttp.getChild("Behavior", ttpNS);
		if (behavior == null) {
			return null;
		}
		Element malware = behavior.getChild("Malware", ttpNS);
		Element exploits = behavior.getChild("Exploits", ttpNS);

		List<Element> list = null;
		if (malware != null && exploits == null) {
			list = malware.getChildren();
			if (list.size() < 2) {
				return null;
			} 
			malware.detach();
			Element element = list.get(0);
			Element parent = copyElement(element.getParentElement());
			list.remove(0);
			parent.setContent(element);
			Map<String, Element> map = splitTTP(ttp, list);
			behavior.setContent(parent);
			setRelatedTTPs(ttp, map);
			return map;
		} else if (malware == null && exploits != null) {
			list = exploits.getChildren();
			if (list.size() < 2) {
				return null;
			}
			exploits.detach();
			Element element = list.get(0);
			Element parent = copyElement(element.getParentElement());
			list.remove(0);
			parent.setContent(element);
			Map<String, Element> map = splitTTP(ttp, list);
			behavior.setContent(parent);
			setRelatedTTPs(ttp, map);
			return map;
		} else if (malware != null && exploits != null) {
			malware.detach();
			exploits.detach();
			list = malware.getChildren();
			Element element = list.get(0);
			Element parent = copyElement(element.getParentElement());
			list.remove(0);
			parent.setContent(element);
			Map<String, Element> map = splitTTP(ttp, list);
			list = exploits.getChildren();
			map.putAll(splitTTP(ttp, list));
			behavior.setContent(parent);
			setRelatedTTPs(ttp, map);
			return map;
		}

		return null;
	}

	private static Map<String, Element> splitTTP(Element ttp, List<Element> list) {
		Map<String, Element> map = new HashMap<String, Element>();
		Iterator<Element> iterator = list.iterator();
		while (iterator.hasNext()) {
			Element element = iterator.next();
			Element parent = copyElement(element.getParentElement());
			iterator.remove();
			parent.setContent(element);
			Element clone = ttp.clone().detach();
			clone.getChild("Behavior", ttpNS).setContent(parent);
			Attribute id = new Attribute("id", "stucco:TTP-" + UUID.randomUUID().toString());
			clone.setAttribute(id);
			clone.addNamespaceDeclaration(stuccoNS);
			map.put(id.getValue(), clone);
		}

		return map;
	}

	private static Element copyElement(Element element) {
		Element clone = new Element(element.getName(), element.getNamespace());
		List<Attribute> attrList = element.getAttributes();
		for (Attribute attr : attrList) {
			clone.setAttribute(attr.clone().detach());
		}
		List<Namespace> nsList = element.getNamespacesIntroduced();
		for (Namespace ns : nsList) {
			clone.addNamespaceDeclaration(ns);
		}

		return clone;
	}

	private static void setRelatedTTPs(Element ttp, Map<String, Element> map) {
		Element relatedTTPs = ttp.getChild("Related_TTPs", ttpNS);
		if (relatedTTPs == null) {
			relatedTTPs = new Element("Related_TTPs", ttpNS);
			ttp.addContent(relatedTTPs);
		}
		for (String id : map.keySet()) {
			Element relatedTTP = new Element("Related_TTP", ttpNS);
			Element ttpReference = new Element("TTP", stixCommonNS);
			ttpReference.setAttribute("idref", id);
			relatedTTP.setContent(ttpReference);
			relatedTTPs.addContent(relatedTTP);
		}
		ttp.sortChildren(new TTPComparator());
	}
}













