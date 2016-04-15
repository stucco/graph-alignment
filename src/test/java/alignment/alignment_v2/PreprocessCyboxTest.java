package alignment.alignment_v2;

import static org.junit.Assert.*;

import javax.xml.namespace.QName;

import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import org.json.JSONObject;
import org.json.JSONArray;

import org.junit.Test;				 

import org.jdom2.Element;
import org.jdom2.Document;
import org.jdom2.Namespace;
import org.jdom2.Attribute; 
import org.jdom2.output.XMLOutputter; 
import org.jdom2.output.Format;

import org.mitre.cybox.cybox_2.Observable; 
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.stix.stix_1.STIXPackage;
import java.io.StringReader;  
import java.io.IOException;
import java.io.File;

import java.nio.file.Files;
import java.nio.file.Paths;

public class PreprocessCyboxTest {


	/*
	 * Tests normalize cybox: extracting Address from Flow, IP from Address, Port from Address
	 */
	@Test
	public void test_flow_address_ip_port() {
		System.out.println("alignment.alignment_v2.test_flow_address_ip_port()");
		try {
			String xml = 
			  "<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<cybox:Observable " +
				"	 id=\"Observable-0a02b096-a29c-4d09-b75b-508ffoy6d08b\" " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:NetFlowObj=\"http://cybox.mitre.org/objects#NetworkFlowObject-2\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" xmlns:cybox=\"http://cybox.mitre.org/cybox-2\"> " +
				"    <cybox:Object> " +
				"        <cybox:Description>ip 000.000.000.111, port 11 to ip 000.000.000.222, port 22</cybox:Description> " +
				"        <cybox:Properties " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetFlowObj:NetworkFlowObjectType\"> " +
				"            <NetFlowObj:Network_Flow_Label> " +
				"                <NetFlowObj:Src_Socket_Address> " +
				"                    <SocketAddressObj:IP_Address> " +
				"                        <AddressObj:Address_Value>000.000.000.111</AddressObj:Address_Value> " +
				"                    </SocketAddressObj:IP_Address> " +
				"                    <SocketAddressObj:Port> " +
				"                        <PortObj:Port_Value>11</PortObj:Port_Value> " +
				"                    </SocketAddressObj:Port> " +
				"                </NetFlowObj:Src_Socket_Address> " +
				"                <NetFlowObj:Dest_Socket_Address> " +
				"                    <SocketAddressObj:IP_Address> " +
				"                        <AddressObj:Address_Value>000.000.000.222</AddressObj:Address_Value> " +
				"                    </SocketAddressObj:IP_Address> " +
				"                    <SocketAddressObj:Port> " +
				"                        <PortObj:Port_Value>22</PortObj:Port_Value> " +
				"                    </SocketAddressObj:Port> " +
				"                </NetFlowObj:Dest_Socket_Address> " +
				"            </NetFlowObj:Network_Flow_Label> " +
				"        </cybox:Properties> " +
				"    </cybox:Object> " +
				"</cybox:Observable> ";

			Observable original = new Observable().fromXMLString(xml);
			assertTrue(original.validate());
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Element observableElement = PreprocessSTIX.parseXMLText(xml).getRootElement();
			Map<String, Element> normalizedElements = PreprocessCybox.normalizeCybox(observableElement);
			normalizedElements.put(observableElement.getAttributeValue("id"), observableElement);
			for (String id : normalizedElements.keySet()) {
				String observable = new XMLOutputter(Format.getPrettyFormat()).outputString(normalizedElements.get(id)); 
				Observable obs = new Observable().fromXMLString(observable);
				assertTrue(obs.validate());
			}

			GraphConstructor graphConstructor = new GraphConstructor();
			JSONObject graph = graphConstructor.constructGraph(normalizedElements);
			JSONObject vertices = graph.getJSONObject("vertices");
		
			XMLOutputter xmlOutputter = new XMLOutputter(Format.getPrettyFormat());
			assertTrue(normalizedElements.size() == 7);

			System.out.println("Testing Flow -> Source Address ... ");
			Observable observable = new Observable().fromXMLString(xmlOutputter.outputString(observableElement));
			assertTrue(observable.validate());
			Element object = observableElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			Element networkFlowLabel = properties.getChild("Network_Flow_Label", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Element sourceSocketAddress = networkFlowLabel.getChild("Src_Socket_Address", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Attribute srcIdrefAttr = sourceSocketAddress.getAttribute("object_reference");
			assertNotNull(srcIdrefAttr);
			String srcIdref = srcIdrefAttr.getValue();
			assertTrue(normalizedElements.containsKey(srcIdref));

			System.out.println("Testing Flow -> Description Address ... ");
			Element destSocketAddress = networkFlowLabel.getChild("Dest_Socket_Address", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Attribute destIdrefAttr = destSocketAddress.getAttribute("object_reference");
			assertNotNull(destIdrefAttr);
			String destIdref = destIdrefAttr.getValue();
			assertTrue(normalizedElements.containsKey(destIdref));

			System.out.println("Testing (Source) Address ... ");
			Element sourceSocketElement = normalizedElements.get(srcIdref);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(sourceSocketElement));
			assertTrue(observable.validate());
			object = sourceSocketElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));

			System.out.println("Testing (Source) Address -> IP ...");
			Element ipAddress = properties.getChild("IP_Address", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute sourceIpIdref = ipAddress.getAttribute("object_reference");
			assertNotNull(sourceIpIdref);
			String sourceIpId = sourceIpIdref.getValue();
			assertTrue(normalizedElements.containsKey(sourceIpId));
			System.out.println("Testing (Source) Address -> Port ...");
			Element portAddress = properties.getChild("Port", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute sourcePortIdref = portAddress.getAttribute("object_reference");
			assertNotNull(sourcePortIdref);
			String sourcePortId = sourcePortIdref.getValue();
			assertTrue(normalizedElements.containsKey(sourcePortId));

			System.out.println("Testing (Source) IP ... ");
			Element sourceIpElement = normalizedElements.get(sourceIpId);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(sourceIpElement));
			assertTrue(observable.validate());
			object = sourceIpElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			ipAddress = properties.getChild("Address_Value", Namespace.getNamespace("AddressObj", "http://cybox.mitre.org/objects#AddressObject-2"));
			assertEquals(ipAddress.getText(), "000.000.000.111");

			System.out.println("Testing (Source) Port ... ");
			Element sourcePortElement = normalizedElements.get(sourcePortId);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(sourcePortElement));
			assertTrue(observable.validate());
			object = sourcePortElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			portAddress = properties.getChild("Port_Value", Namespace.getNamespace("PortObj", "http://cybox.mitre.org/objects#PortObject-2"));
			assertEquals(portAddress.getText(), "11");

			System.out.println("Testing (Destination) Address ... ");
			Element destSocketElement = normalizedElements.get(destIdref);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(destSocketElement));
			assertTrue(observable.validate());
			object = destSocketElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));

			System.out.println("Testing (Destination) Address -> IP ...");
			ipAddress = properties.getChild("IP_Address", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute destIpIdref = ipAddress.getAttribute("object_reference");
			assertNotNull(destIpIdref);
			String destIpId = destIpIdref.getValue();
			assertTrue(normalizedElements.containsKey(destIpId));
			System.out.println("Testing (Destination) Address -> Port ...");
			portAddress = properties.getChild("Port", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute destPortIdref = portAddress.getAttribute("object_reference");
			assertNotNull(destPortIdref);
			String destPortId = destPortIdref.getValue();
			assertTrue(normalizedElements.containsKey(destPortId));

			System.out.println("Testing (Destination) IP ... ");
			Element destIpElement = normalizedElements.get(destIpId);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(destIpElement));
			assertTrue(observable.validate());
			object = destIpElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			ipAddress = properties.getChild("Address_Value", Namespace.getNamespace("AddressObj", "http://cybox.mitre.org/objects#AddressObject-2"));
			assertEquals(ipAddress.getText(), "000.000.000.222");

			System.out.println("Testing (Destination) Port ... ");
			Element destPortElement = normalizedElements.get(destPortId);
			observable = new Observable().fromXMLString(xmlOutputter.outputString(destPortElement));
			assertTrue(observable.validate());
			object = destPortElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			portAddress = properties.getChild("Port_Value", Namespace.getNamespace("PortObj", "http://cybox.mitre.org/objects#PortObject-2"));
			assertEquals(portAddress.getText(), "22");

			assertTrue(true);
		} catch (Exception e) { 
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize cybox: HTTPSession, DNSRecord, Address, IP, Port, DNSName
	 */
	//@Test
	public void test_httpsession_dnsrecord_address_ip_port_domainname() {
		System.out.println("alignment.alignment_v2.test_dnsrecord_address_ip_port_domainname()");
		try {
			String xml = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<cybox:Observable " +
				"    id=\"stucco:NetworkConnection-a181a22e-ebf6-4034-9953-e24849c24245\" " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:DNSQueryObj=\"http://cybox.mitre.org/objects#DNSQueryObject-2\" " +
				"    xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\" " +
				"    xmlns:HTTPSessionObj=\"http://cybox.mitre.org/objects#HTTPSessionObject-2\" " +
				"    xmlns:NetworkConnectionObj=\"http://cybox.mitre.org/objects#NetworkConnectionObject-2\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" " +
				"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <cybox:Object> " +
				"        <cybox:Properties " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkConnectionObj:NetworkConnectionObjectType\"> " +
				"            <NetworkConnectionObj:Source_Socket_Address> " +
				"                <SocketAddressObj:IP_Address> " +
				"                    <AddressObj:Address_Value>000.000.000.111</AddressObj:Address_Value> " +
				"                </SocketAddressObj:IP_Address> " +
				"                <SocketAddressObj:Port> " +
				"                    <PortObj:Port_Value>11</PortObj:Port_Value> " +
				"                </SocketAddressObj:Port> " +
				"            </NetworkConnectionObj:Source_Socket_Address> " +
				"            <NetworkConnectionObj:Destination_Socket_Address> " +
				"                <SocketAddressObj:IP_Address> " +
				"                    <AddressObj:Address_Value>000.000.000.222</AddressObj:Address_Value> " +
				"                </SocketAddressObj:IP_Address> " +
				"                <SocketAddressObj:Port> " +
				"                    <PortObj:Port_Value>22</PortObj:Port_Value> " +
				"                </SocketAddressObj:Port> " +
				"            </NetworkConnectionObj:Destination_Socket_Address> " +
				"            <NetworkConnectionObj:Layer7_Connections> " +
				"                <NetworkConnectionObj:HTTP_Session> " +
				"                    <HTTPSessionObj:HTTP_Request_Response> " +
				"                        <HTTPSessionObj:HTTP_Client_Request> " +
				"                            <HTTPSessionObj:HTTP_Request_Line> " +
				"                                <HTTPSessionObj:Value>http request client line</HTTPSessionObj:Value> " +
				"                            </HTTPSessionObj:HTTP_Request_Line> " +
				"                        </HTTPSessionObj:HTTP_Client_Request> " +
				"                        <HTTPSessionObj:HTTP_Server_Response> " +
				"                            <HTTPSessionObj:HTTP_Status_Line> " +
				"                                <HTTPSessionObj:Version>Response Version</HTTPSessionObj:Version> " +
				"                                <HTTPSessionObj:Status_Code>200</HTTPSessionObj:Status_Code> " +
				"                                <HTTPSessionObj:Reason_Phrase>Reason Phrase</HTTPSessionObj:Reason_Phrase> " +
				"                            </HTTPSessionObj:HTTP_Status_Line> " +
				"                            <HTTPSessionObj:HTTP_Response_Header> " +
				"                                <HTTPSessionObj:Raw_Header>Raw Header</HTTPSessionObj:Raw_Header> " +
				"                            </HTTPSessionObj:HTTP_Response_Header> " +
				"                            <HTTPSessionObj:HTTP_Message_Body> " +
				"                                <HTTPSessionObj:Message_Body>Message Body</HTTPSessionObj:Message_Body> " +
				"                            </HTTPSessionObj:HTTP_Message_Body> " +
				"                        </HTTPSessionObj:HTTP_Server_Response> " +
				"                    </HTTPSessionObj:HTTP_Request_Response> " +
				"                </NetworkConnectionObj:HTTP_Session> " +
				"                <NetworkConnectionObj:DNS_Query> " +
				"                    <DNSQueryObj:Transaction_ID>4857230</DNSQueryObj:Transaction_ID> " +
				"                    <DNSQueryObj:Question> " +
				"                        <DNSQueryObj:QName> " +
				"                            <URIObj:Value>domain.com</URIObj:Value> " +
				"                        </DNSQueryObj:QName> " +
				"                    </DNSQueryObj:Question> " +
				"                    <DNSQueryObj:Answer_Resource_Records> " +
				"                        <DNSQueryObj:Resource_Record> " +
				"                            <DNSRecordObj:Description>DNSRecord Description</DNSRecordObj:Description> " +
				"                            <DNSRecordObj:Domain_Name> " +
				"                                <URIObj:Value>domain.com</URIObj:Value> " +
				"                            </DNSRecordObj:Domain_Name> " +
				"                            <DNSRecordObj:IP_Address> " +
				"                                <AddressObj:Address_Value>100.100.100.100</AddressObj:Address_Value> " +
				"                            </DNSRecordObj:IP_Address> " +
				"                        </DNSQueryObj:Resource_Record> " +
				"                    </DNSQueryObj:Answer_Resource_Records> " +
				"                </NetworkConnectionObj:DNS_Query> " +
				"            </NetworkConnectionObj:Layer7_Connections> " +
				"        </cybox:Properties> " +
				"    </cybox:Object> " +
				"</cybox:Observable> ";

			Observable original = new Observable().fromXMLString(xml);
			assertTrue(original.validate());

			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Element observableElement = PreprocessSTIX.parseXMLText(xml).getRootElement();
			Map<String, Element> normalizedElements = PreprocessCybox.normalizeCybox(observableElement);
			normalizedElements.put(observableElement.getAttributeValue("id"), observableElement);
			
			GraphConstructor graphConstructor = new GraphConstructor();
			JSONObject graph = graphConstructor.constructGraph(normalizedElements);
			JSONObject vertices = graph.getJSONObject("vertices");
			assertTrue(normalizedElements.size() == 13);

			for (String key : normalizedElements.keySet()) {
				Element element = normalizedElements.get(key);
				xml = new XMLOutputter().outputString(element);
				Observable observable = new Observable().fromXMLString(xml);
			//	assertTrue(observable.validate());	
			}

		} catch (Exception e) { 
			e.printStackTrace();
			fail("Exception");
		}
	}

	//@Test
	public void test_samples() {
		System.out.println("alignment.test_samples()");
		try {
			File folder = new File("./resources/samples/samples/");
			for (File file : folder.listFiles()) {
				String xml = new String(Files.readAllBytes(Paths.get(file.getPath())));
				Map<String, Element> normalizedElements = new HashMap<String, Element>();
				Observables observables = new Observables().fromXMLString(xml);
				List<Observable> observableList = observables.getObservables();
				for (Observable observable : observableList) {
					if (observable.getId() == null) {
						observable.setId(new QName("gov.ornl.stucco", "Observable" + "-" + UUID.randomUUID().toString(), "stucco"));
					}
					PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
					Element observableElement = preprocessSTIX.parseXMLText(observable.toXMLString()).getRootElement();
					normalizedElements.putAll(PreprocessCybox.normalizeCybox(observableElement));
					normalizedElements.put(observableElement.getAttributeValue("id"), observableElement);
					for (String id : normalizedElements.keySet()) {
						String observableString = new XMLOutputter(Format.getPrettyFormat()).outputString(normalizedElements.get(id)); 
					}
				}
				GraphConstructor graphConstructor = new GraphConstructor();
				JSONObject graph = graphConstructor.constructGraph(normalizedElements);
				JSONObject vertices = graph.getJSONObject("vertices");
			}
		
			assertTrue(true);
		} catch (Exception e) { 
			e.printStackTrace();
			fail("Exception");
		}
	}
}



