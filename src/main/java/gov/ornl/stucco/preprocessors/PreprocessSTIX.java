//TODO: clean, add ttp and exploit_target preprocessing
//TODO: edit observable preprocessing to handle observable events ... and when there are no objects ...
//TODO: fix xpath/path with OR
package gov.ornl.stucco.preprocessors;

import gov.ornl.stucco.ConfigFileLoader;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;  
import java.util.UUID;  
import java.util.Iterator;  
import java.util.ArrayDeque;    
import java.io.StringWriter; 

import java.io.StringReader;     
import java.io.IOException;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format; 
import org.jdom2.Document;
import org.jdom2.Element; 
import org.jdom2.Namespace;
import org.jdom2.JDOMException;
import org.jdom2.input.StAXStreamBuilder;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.events.XMLEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;

public class PreprocessSTIX {

  public class Vertex { 
    public String id;
    public String xml;
    public String type;
    public String observableType;
    public Map<String, List<Object>> contentPaths;
    public Map<String, List<String>> referencePaths;

    public Vertex() {}

    public void print() {
      System.out.println("ID: " + id);
      System.out.println("type: " + type);
      System.out.println("observableType: " + observableType);
      System.out.println("XML: " + xml);
    
      Element e = parseXMLText(xml).getRootElement();
      XMLOutputter xml = new XMLOutputter();
      xml.setFormat(Format.getPrettyFormat());
      System.out.println(xml.outputString(e));
      
      for (String path : contentPaths.keySet()) {
        System.out.println(path + ": " + contentPaths.get(path));
      }
      for (String key : referencePaths.keySet()) {
        System.out.println(key + ": " + referencePaths.get(key));
      }
    }
  }

  private Map<String, Vertex> vertices;

  private static final Logger logger = LoggerFactory.getLogger(PreprocessSTIX.class);
  private static final Map<String, Namespace> stixElementMap;
  private static final Map<String, String> stixTypes;
  private static Map<String, String> globalNS;
  private static XMLInputFactory inputFactory;
  private static XMLOutputFactory outputFactory;

  /**
   * Normalizing STIX packges by removing nested elements.
   *
   * @author Maria Vincent
   */

  static {
    /* stix elements wrapers */
    Map<String, String> map = new HashMap<String, String>();
    map.put("Indicator", "indicator:IndicatorType");
    map.put("TTP", "ttp:TTPType"); 
    map.put("Exploit_Target", "et:ExploitTargetType");
    map.put("Incident", "incident:IncidentType");
    map.put("Course_Of_Action", "coa:CourseOfActionType");
    map.put("Campaign", "campaign:CampaignType");
    map.put("Threat_Actor", "ta:ThreatActorType");
    stixTypes = Collections.unmodifiableMap(map);

    Map<String, Namespace> nsmap = new HashMap<String, Namespace>();
    nsmap.put("Observable", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
    nsmap.put("Exploit_Target", Namespace.getNamespace("et", "http://stix.mitre.org/ExploitTarget-1"));
    nsmap.put("Course_Of_Action", Namespace.getNamespace("coa", "http://stix.mitre.org/CourseOfAction-1"));
    nsmap.put("Indicator", Namespace.getNamespace("indicator", "http://stix.mitre.org/Indicator-2"));
    nsmap.put("TTP", Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1"));
    nsmap.put("Incident", Namespace.getNamespace("incident", "http://stix.mitre.org/Incident-1"));
    nsmap.put("Campaign", Namespace.getNamespace("campaign", "http://stix.mitre.org/Campaign-1"));
    nsmap.put("Threat_Actor", Namespace.getNamespace("ta", "http://stix.mitre.org/ThreatActor-1"));
    stixElementMap = Collections.unmodifiableMap(nsmap);
  }

  public PreprocessSTIX() {
    outputFactory = XMLOutputFactory.newInstance();
    inputFactory = XMLInputFactory.newInstance();
    inputFactory.setProperty(inputFactory.IS_COALESCING, true);
  }

  public void print(Element e) {
    XMLOutputter xml = new XMLOutputter();
    xml.setFormat(Format.getPrettyFormat());
    System.out.println(xml.outputString(e));
  }

  /*
  * Parses xml String and converts it to jdom2 Document
  */ 
  public static Document parseXMLText(String documentText) {
    Document doc = null;
    try {
      XMLInputFactory inputFactory = XMLInputFactory.newInstance();
      XMLStreamReader reader = inputFactory.createXMLStreamReader(new StringReader(documentText));
      StAXStreamBuilder builder = new StAXStreamBuilder();
      doc = builder.build(reader);
    } catch (XMLStreamException e) {
      e.printStackTrace();
    } catch (JDOMException e) {
      e.printStackTrace();
    }

    return doc;
  }

  public void print(String xml) {
    System.out.println(xml);
    Element e = parseXMLText(xml).getRootElement();
    XMLOutputter out = new XMLOutputter();
    out.setFormat(Format.getPrettyFormat());
    System.out.println(out.outputString(e));
  }

  public Map<String, Vertex> normalizeSTIX(String stixString) {
    vertices = new HashMap<String, Vertex>();
    globalNS = new HashMap<String, String>();
    
    stixString = stixString.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
    stixString = "<root>" + stixString + "</root>";

    try {
      StringWriter sw = new StringWriter();
      XMLStreamWriter writer = outputFactory.createXMLStreamWriter(sw);

      XMLStreamReader reader = inputFactory.createFilteredReader(inputFactory.createXMLStreamReader(new StringReader(stixString)),
        new StreamFilter() {
          public boolean accept(XMLStreamReader reader) {
            return !reader.isWhiteSpace();
          }
        }
      );
      while (reader.hasNext() && reader.getEventType() != XMLEvent.END_DOCUMENT) {
        if (reader.getEventType() == XMLEvent.START_ELEMENT) {
          String localName = reader.getLocalName();
          if (stixElementMap.containsKey(localName)) {
            sw.getBuffer().setLength(0);
            if (localName.equals("Observable")) {
              writeObservable(reader, writer, sw);
            } else {
              writeElement(reader, writer, sw);
            }
          } else {
            readNamespaces(reader);
          }
        }
        reader.next();
      }

      writer.close();
      reader.close();
    } catch (XMLStreamException e) {
      e.printStackTrace();
    } 

    return vertices;
  }

  private void readNamespaces(XMLStreamReader reader) {
    for (int i = 0; i < reader.getNamespaceCount(); i++) {
      String prefix = reader.getNamespacePrefix(i);
      String uri = reader.getNamespaceURI(i);
      globalNS.put(prefix, uri);
    }
  }

  private String writeElement(XMLStreamReader reader, XMLStreamWriter writer, StringWriter sw) throws XMLStreamException {
    Vertex vertex = new Vertex();
    vertex.type = reader.getLocalName();
    vertex.contentPaths = new HashMap<String, List<Object>>();
    vertex.referencePaths = new HashMap<String, List<String>>();
    vertex.id = reader.getAttributeValue(null, "id");

    Set<String> idrefSet = new HashSet<String>();
    ArrayDeque<String> path = new ArrayDeque<String>();
    Map<String, String> vertNS = new HashMap<String, String>();
    boolean done = false;
    String pathString = null;
    initElement(reader, writer, vertNS, path, vertex);
    writer.writeAttribute("xmlns", "http://xml/metadataSharing.xsd");

    reader.next();

    while (reader.hasNext()) {
      switch (reader.getEventType()) {
        case XMLEvent.START_ELEMENT:
          String localName = reader.getLocalName();
          
          path.add(localName);
          pathString = toString(path);

          if (stixElementMap.containsKey(localName) && 
            // !reader.getNamespaceURI().equals("http://stix.mitre.org/TTP-1")) {
            (reader.getPrefix().equals("stixCommon") || localName.equals("Observable"))) {
            String idref = reader.getAttributeValue(null, "idref");
            if (idref == null) {
              String prefix = reader.getPrefix();
              String namespaceURI = reader.getNamespaceURI();
              vertNS.put(prefix, namespaceURI);

              StringWriter newSw = new StringWriter();
              XMLStreamWriter newWriter = outputFactory.createXMLStreamWriter(newSw);
              idref = (localName.equals("Observable")) ? writeObservable(reader, newWriter, newSw) : writeElement(reader, newWriter, newSw);
              addToReferenceList(vertex.referencePaths, pathString, idref);

              writer.writeEmptyElement(prefix, localName, namespaceURI);  
              writeIdrefAttribute(writer, idref, vertNS);
      
              if (!localName.equals("Observable")) { 
                writer.writeAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance", "type", stixTypes.get(localName));
                Namespace ns = stixElementMap.get(localName);
                prefix = ns.getPrefix();
                namespaceURI = ns.getURI();
                vertNS.put(prefix, namespaceURI);
              }
              path.removeLast();
            } else {
              addToReferenceList(vertex.referencePaths, pathString, idref);
              writeStartElement(reader, writer, localName, vertNS);
            }
          } else {
            writeStartElement(reader, writer, localName, vertNS);
          }
          break;
        case XMLEvent.END_ELEMENT:
          done = writeEndElement(writer, path);
          break;
        case XMLEvent.CHARACTERS:
          writeCharacters(reader, writer, pathString, vertex.contentPaths);
          break;
      }
        if (done) {
          break;
        } else {
          reader.next();
        }
    }

    vertNS.remove("null");
    vertex.xml = sw.toString().replaceFirst(" ", toString(vertNS));
    vertices.put(vertex.id, vertex);

    return vertex.id;
  }

  private void addToReferenceList(Map<String, List<String>> referencePaths, String pathString, String idref) {
    if (referencePaths.containsKey(pathString)) {
      referencePaths.get(pathString).add(idref); 
    } else {
      List<String> list = new ArrayList<String>();
      list.add(idref);
      referencePaths.put(pathString, list);
    }
  }

  private String writeObservable(XMLStreamReader reader, XMLStreamWriter writer, StringWriter sw) throws XMLStreamException {
    Vertex vertex = new Vertex();
    vertex.type = "Observable";
    vertex.id = reader.getAttributeValue(null, "id");
    vertex.contentPaths = new HashMap<String, List<Object>>();
    vertex.referencePaths = new HashMap<String, List<String>>();

    Set<String> idrefSet = new HashSet<String>();
    ArrayDeque<String> path = new ArrayDeque<String>();
    Map<String, String> vertNS = new HashMap<String, String>();
    Set<String> emptyElements = new HashSet<String>();

    boolean done = false;

    initElement(reader, writer, vertNS, path, vertex);

    reader.next();

    while (reader.hasNext()) {
      switch (reader.getEventType()) {
        case XMLEvent.START_ELEMENT:
          String localName = reader.getLocalName();

          String idref = reader.getAttributeValue(null, "idref");
          if (idref == null) {
            idref = reader.getAttributeValue(null, "object_reference");
          }
          if (idref != null) {
            addToReferenceList(vertex.referencePaths, buildString(toString(path), "/", localName), idref);
            writeStartElement(reader, writer, localName, vertNS);
            path.add(localName);
          } else if (localName.equals("Properties")) {
            String type = reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance", "type");
            JSONObject cyboxType = null;
            if (type != null) {
              type = type.split(":")[1]; 
              cyboxType = ConfigFileLoader.cyboxObjects.getJSONObject(type);
            }
            if (path.getLast().equals("Object")) {
              if (vertex.observableType != null) {
                logger.debug("vertex.observableType IS NOT NULL!");
              } else {
                vertex.observableType = type;
              }
              writeStartElement(reader, writer, localName, vertNS);
              path.add(localName);
              vertNS.putAll(writeObservableProperties(reader, writer, sw, cyboxType, toString(path), vertex));
              continue;
            } else {
              String prefix = reader.getPrefix();
              String namespaceURI = reader.getNamespaceURI();
              vertNS.put(prefix, namespaceURI);
              globalNS.put(prefix, namespaceURI);
              
              writer.writeEmptyElement(prefix, localName, namespaceURI);

              String attrPrefix = null;
              String attrURI = null;
              idref = reader.getAttributeValue(null, "id");

              if (idref == null) {
                idref = makeID("Observable");
                vertNS.put("stucco", "gov.ornl.stucco");
                globalNS.put("stucco", "gov.ornl.stucco");
                attrPrefix = "stucco";
                attrURI = "gov.ornl.stucco";
              } else {
                attrPrefix = getQNamePrefix(idref);
                if (globalNS.containsKey(attrPrefix)) {
                  attrURI = globalNS.get(attrPrefix);
                  vertNS.put(attrPrefix, attrURI);
                }
              }
              addToReferenceList(vertex.referencePaths, buildString(toString(path), "/", localName), idref);
              writer.writeAttribute("object_reference", idref);
              writer.writeAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance", "type", reader.getAttributeValue("http://www.w3.org/2001/XMLSchema-instance", "type"));
              vertNS.put(cyboxType.getString("prefix"), cyboxType.getString("URI"));
              vertNS.put("xsi", "http://www.w3.org/2001/XMLSchema-instance");

              writeNewObservable(reader, type, cyboxType, idref, attrPrefix, attrURI);
            }
          } else if (localName.equals("Observable")) {
            if (path.getLast().equals("Observable_Composition")) {
              if (vertex.observableType != null) {
                logger.debug("OBSERVABLE_COMPOSITION WAS FOUND, BUT vertex.observableType IS ALREADY DEFINED!");
              } else {
                vertex.observableType = "ObservableComposition";
              }
            }
            String prefix = reader.getPrefix();
            String namespaceURI = reader.getNamespaceURI();
            vertNS.put(prefix, namespaceURI);

            StringWriter newSw = new StringWriter();
            XMLStreamWriter newWriter = outputFactory.createXMLStreamWriter(newSw);
            idref = writeObservable(reader, newWriter, newSw);
            addToReferenceList(vertex.referencePaths, buildString(toString(path), "/", localName), idref);

            String idrefPrefix = getQNamePrefix(idref);
            if (globalNS.containsKey(idrefPrefix)) {
              String idrefURI = globalNS.get(idrefPrefix);
              vertNS.put(idrefPrefix, idrefURI);
            }

            writer.writeEmptyElement(prefix, localName, namespaceURI);  
            writeIdrefAttribute(writer, idref, vertNS);

          } else {
            if (localName.equals("Event") && vertex.observableType == null) {
              vertex.observableType = "Event";
            } else if (localName.equals("Observable_Composition") && vertex.observableType == null) {
              vertex.observableType = "ObservableComposition";
            }
            writeStartElement(reader, writer, localName, vertNS);
            path.add(localName);
          }

          break;
        case XMLEvent.END_ELEMENT:
          done = writeEndElement(writer, path);
          break;
        case XMLEvent.CHARACTERS:
          writeCharacters(reader, writer, toString(path), vertex.contentPaths);
          break;
      }
        if (done) {
          break;
        } else {
          reader.next();
        }
    }

    String xml = sw.toString();
    if (vertex.id == null) {
      vertex.id = makeID(vertex.type);
      vertNS.put("stucco", "gov.ornl.stucco");
      globalNS.put("stucco", "gov.ornl.stucco");
      xml = xml.replaceFirst(" ", new StringBuilder(" id=\"").append(vertex.id).append("\" ").toString());
      vertex.id = makeID(vertex.type);
    } else {
      String idPrefix = getQNamePrefix(vertex.id);
      if (globalNS.containsKey(idPrefix)) {
        vertNS.put(idPrefix, globalNS.get(idPrefix));
      }
    }
    Namespace ns = stixElementMap.get(vertex.type);
    vertNS.remove("null");
    vertNS.put(ns.getPrefix(), ns.getURI());
    vertex.xml = xml.replaceFirst(" ", toString(vertNS));
    vertices.put(vertex.id, vertex);

    return vertex.id;
  }

  private Map<String, String> writeObservableProperties(XMLStreamReader reader, XMLStreamWriter writer, StringWriter sw, JSONObject cyboxType, String prePath, Vertex vertex) throws XMLStreamException {
    Set<String> idrefSet = new HashSet<String>();
    Set<String> emptyElements = new HashSet<String>();
    ArrayDeque<String> path = new ArrayDeque<String>();
    Map<String, String> vertNS = new HashMap<String, String>();

    boolean done = false;
    String pathString = null;

    reader.next();
    if (reader.getEventType() != XMLEvent.END_ELEMENT) {
      while (reader.hasNext()) {

        switch(reader.getEventType()) {
          case XMLEvent.START_ELEMENT:
            String localName = reader.getLocalName();
            path.add(localName);
            pathString = buildString(prePath, "/", toString(path));

            String propertyType = getPropertyType(localName, cyboxType);

            String idref = reader.getAttributeValue(null, "idref");
            if (idref == null) {
              idref = reader.getAttributeValue(null, "object_reference");
            }
            if (idref != null) {
              addToReferenceList(vertex.referencePaths, pathString, idref);
              writeStartElement(reader, writer, localName, vertNS);
            } else if (ConfigFileLoader.cyboxObjects.has(propertyType)) {
              JSONObject cyboxObject = ConfigFileLoader.cyboxObjects.optJSONObject(propertyType);
              if (cyboxObject.has("objectReference")) {
                String prefix = reader.getPrefix();
                String namespaceURI = reader.getNamespaceURI();
                writer.writeEmptyElement(prefix, localName, namespaceURI);
                vertNS.put(prefix, namespaceURI);

                String objectReference = reader.getAttributeValue(null, "id");
                String attrPrefix = null;
                String attrURI = null;
                if (objectReference == null) {
                  objectReference = makeID("Observable");
                  attrPrefix = "stucco";
                  attrURI = "gov.ornl.stucco";
                  vertNS.put(attrPrefix, attrURI);
                  globalNS.put(attrPrefix, attrURI);
                } else {
                  attrPrefix = getQNamePrefix(objectReference);
                  if (globalNS.containsKey(attrPrefix)) {
                    attrURI = globalNS.get(attrPrefix);
                    vertNS.put(attrPrefix, attrURI);
                  } else {
                    logger.debug("Could not find URI for prefix: " + attrPrefix);
                  }
                }

                addToReferenceList(vertex.referencePaths, pathString, objectReference);
                writer.writeAttribute("object_reference", objectReference);
                writeNewObservable(reader, propertyType, cyboxObject, objectReference, attrPrefix, attrURI);
                emptyElements.add(localName);
                path.removeLast();
              } else { 
                writeStartElement(reader, writer, localName, vertNS);
                vertNS.putAll(writeObservableProperties(reader, writer, sw, ConfigFileLoader.cyboxObjects.optJSONObject(propertyType), pathString, vertex));
              }
              continue;
            } else {
              writeStartElement(reader, writer, localName, vertNS);
            }
            break;
          case XMLEvent.END_ELEMENT:
            done = (emptyElements.contains(reader.getLocalName())) ? path.isEmpty() : writeEndElement(writer, path);
            break;
          case XMLEvent.CHARACTERS:
            if (pathString == null) {
               writeCharacters(reader, writer, prePath, vertex.contentPaths);
            } else {
               writeCharacters(reader, writer, pathString, vertex.contentPaths);
            }
           
            done = path.isEmpty();
            break;
        }
        reader.next();
        if (done) {
          if (reader.getEventType() == XMLEvent.START_ELEMENT) {
            done = false;
            continue;
          } else {
            break;
          }
        }
      }
    }

    return vertNS;
  }

  private void writeNewObservable(XMLStreamReader reader, String type, JSONObject cyboxType, String id, String idPrefix, String idURI) throws XMLStreamException {
    StringWriter sw = new StringWriter();
    XMLOutputFactory factory = XMLOutputFactory.newInstance();
    XMLStreamWriter writer = factory.createXMLStreamWriter(sw);
    Map<String, String> vertNS = new HashMap<String, String>();
    Vertex vertex = new Vertex();
    vertex.contentPaths = new HashMap<String, List<Object>>();
    vertex.referencePaths = new HashMap<String, List<String>>();
    vertex.type = "Observable";
    vertex.observableType = type; //cyboxType.getString("typeName");

    vertex.id = id;
    if (idPrefix != null) {
      vertNS.put(idPrefix, idURI);
    }

    vertNS.put("cybox", "http://cybox.mitre.org/cybox-2");
    vertNS.put("xsi", "http://www.w3.org/2001/XMLSchema-instance");
    vertNS.put(cyboxType.getString("prefix"), cyboxType.getString("URI"));
    
    writer.writeStartElement("cybox", "Observable", "http://cybox.mitre.org/cybox-2");
    writer.writeAttribute("id", vertex.id);
    writer.writeStartElement("cybox", "Object", "http://cybox.mitre.org/cybox-2");
    writer.writeStartElement("cybox", "Properties", "http://cybox.mitre.org/cybox-2");
    writer.writeAttribute("xsi", "http://www.w3.org/2001/XMLSchema-instance", "type", cyboxType.getString("prefix") + ":" + type);

    vertNS.putAll(writeObservableProperties(reader, writer, sw, cyboxType, "Observable/Object/Properties", vertex));

    writer.writeEndElement();
    writer.writeEndElement();
    writer.writeEndElement();
    
    Namespace ns = stixElementMap.get(vertex.type);
    vertNS.put(ns.getPrefix(), ns.getURI());
    String xml = sw.toString();
    vertex.xml = xml.replaceFirst(" ", toString(vertNS));
    vertices.put(vertex.id, vertex);
  }

  private void writeStartElement(XMLStreamReader reader, XMLStreamWriter writer, String localName, Map<String, String> vertNS) throws XMLStreamException {
    String prefix = reader.getPrefix();
    String namespaceURI = reader.getNamespaceURI();
    vertNS.put(prefix, namespaceURI);
    globalNS.put(prefix, namespaceURI);
    writer.writeStartElement(prefix, localName, namespaceURI);
    writeNamespaces(reader, vertNS);
    writeAttributes(reader, writer, vertNS);
  }

  private void writeNamespaces(XMLStreamReader reader, Map<String, String> vertNS) {
    for (int i = 0; i < reader.getNamespaceCount(); i++) {
        String prefix = reader.getNamespacePrefix(i);
        String namespaceURI = reader.getNamespaceURI(i);
        globalNS.put(prefix, namespaceURI);
        vertNS.put(prefix, namespaceURI);
    }
  }

  private void writeAttributes(XMLStreamReader reader, XMLStreamWriter writer, Map<String, String> vertNS) throws XMLStreamException {
    for (int i = 0; i < reader.getAttributeCount(); i++) {
      String attValue = reader.getAttributeValue(i);
      String attName = reader.getAttributeLocalName(i);

      String prefix = getQNamePrefix(attValue);
      if (prefix != null && globalNS.containsKey(prefix)) {
        vertNS.put(prefix, globalNS.get(prefix));
      } 

      String attUri = reader.getAttributeNamespace(i);
      if (attUri != null) {
        prefix = reader.getAttributePrefix(i);
        writer.writeAttribute(prefix, attUri, attName, attValue);
        vertNS.put(prefix, attUri);
        globalNS.put(prefix, attUri);
      } else {
        writer.writeAttribute(attName, attValue);
      }
    }
  }

  private boolean writeEndElement(XMLStreamWriter writer, ArrayDeque<String> path) throws XMLStreamException {
    writer.writeEndElement();
    if (!path.isEmpty()) {
      path.removeLast();
    }
    boolean done = path.isEmpty();

    return done;
  }

  private void writeCharacters(XMLStreamReader reader, XMLStreamWriter writer, String pathString, Map<String, List<Object>> contentPaths) throws XMLStreamException {
    if (reader.hasText()) {
      List<Object> list = contentPaths.get(pathString);
      if (list == null) {
        list = new ArrayList<Object>();
      }
      list.add(reader.getText());
      contentPaths.put(pathString, list);
    }
    writer.writeCharacters(reader.getTextCharacters(), reader.getTextStart(), reader.getTextLength());
  }

  private void writeIdrefAttribute(XMLStreamWriter writer, String idref, Map<String, String> vertNS) throws XMLStreamException {
    writer.writeAttribute("idref", idref);
    String idrefPrefix = getQNamePrefix(idref);
    if (globalNS.containsKey(idrefPrefix)) {
      String idrefURI = globalNS.get(idrefPrefix);
      vertNS.put(idrefPrefix, idrefURI);
    }
  }

  private void initElement(XMLStreamReader reader, XMLStreamWriter writer, Map<String, String> vertNS, ArrayDeque<String> path, Vertex vertex) throws XMLStreamException {
    String localName = reader.getLocalName();
    Namespace ns = stixElementMap.get(localName);
    String prefix = ns.getPrefix();
    String namespaceURI = ns.getURI();
    vertNS.put(prefix, namespaceURI);
    globalNS.put(prefix, namespaceURI);
    writer.writeStartElement(prefix, localName, namespaceURI);

    writeNamespaces(reader, vertNS);
    writeAttributes(reader, writer, vertNS);
    if (vertex.id == null) {
      vertex.id = makeID(vertex.type);
      vertNS.put("stucco", "gov.ornl.stucco");
      globalNS.put("stucco", "gov.ornl.stucco");
      writer.writeAttribute("id", vertex.id);
    }
    path.add(localName);
  }

  private String getQNamePrefix(String qname) {
    String prefix = null;

    if (qname.contains(":")) {
      prefix = qname.split(":")[0];
    }

    return prefix;
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

  private String makeID(String type) {
    StringBuilder sb = new StringBuilder();
    sb.append("stucco:");
    sb.append(type);
    sb.append("-");
    sb.append(UUID.randomUUID().toString());
    
    return sb.toString();
  }
  
  private String toString(ArrayDeque<String> set) {
    if (set.isEmpty()) {
      return "";
    }

    StringBuilder sb = new StringBuilder();
    Iterator<String> iter = set.iterator();
    while (iter.hasNext()) {
      sb.append("/");
      sb.append(iter.next());
    }
    sb.deleteCharAt(0);
  
    return sb.toString(); 
  }

  private String toString(Map<String, String> map) {
    StringBuilder sb = new StringBuilder();

    for (Map.Entry<String, String> entry : map.entrySet()) {
      sb.append(" xmlns:");
      sb.append(entry.getKey());
      sb.append("=\"");
      sb.append(entry.getValue());
      sb.append("\"");
    }
    sb.append(" ");

    return sb.toString();
  }

  public void print(int eventType) {
    switch (eventType) {
        case XMLEvent.START_ELEMENT:
          System.out.println(" ** START_ELEMENT ** ");
          break;

        case XMLEvent.END_ELEMENT:
            System.out.println(" ** END_ELEMENT ** ");
            break;

        case XMLEvent.PROCESSING_INSTRUCTION:
            System.out.println(" ** PROCESSING_INSTRUCTION ** ");
            break;

        case XMLEvent.CHARACTERS:
            System.out.println(" ** CHARACTERS ** ");
            break;

        case XMLEvent.COMMENT:
            System.out.println(" ** COMMENT ** ");
            break;

        case XMLEvent.START_DOCUMENT:
            System.out.println(" ** START_DOCUMENT ** ");
            break;

        case XMLEvent.END_DOCUMENT:
            System.out.println(" ** END_DOCUMENT ** ");
            break;

        case XMLEvent.ENTITY_REFERENCE:
            System.out.println(" ** ENTITY_REFERENCE ** ");
            break;

        case XMLEvent.ATTRIBUTE:
            System.out.println(" ** ATTRIBUTE ** ");
            break;

        case XMLEvent.DTD:
            System.out.println(" ** DTD ** ");
            break;

        case XMLEvent.CDATA:
            System.out.println(" ** CDATA ** ");
            break;

        case XMLEvent.SPACE:
            System.out.println(" ** SPACE ** ");
            break;
    }
  }

  /**
  * concatenates multiple substrings 
  */
  protected static String buildString(Object... substrings) {
      StringBuilder str = new StringBuilder();
      for (Object substring : substrings) {
          str.append(substring);
      }

      return str.toString();
  }
}