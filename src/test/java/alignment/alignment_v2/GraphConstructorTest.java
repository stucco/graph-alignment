package alignment.alignment_v2;

import alignment.alignment_v2.PreprocessSTIX;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

import org.jdom2.output.XMLOutputter;
import org.jdom2.xpath.*;
import org.jdom2.*;

import org.xml.sax.SAXException;
import org.mitre.stix.stix_1.*;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.common_1.CourseOfActionBaseType;
import org.mitre.stix.indicator_2.Indicator; 
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.campaign_1.Campaign;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.common_1.ExploitTargetBaseType;
import org.mitre.stix.incident_1.Incident;
import org.mitre.stix.threatactor_1.ThreatActor;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.common_1.TTPBaseType;
import org.mitre.stix.common_1.IncidentBaseType;
import org.mitre.stix.common_1.CampaignBaseType;
import org.mitre.stix.common_1.ThreatActorBaseType;

/**
 * Unit test for STIX GraphConstructor
 */
public class GraphConstructorTest {

	String[] allVerts = {"Account", "Organization", "Address", "AddressRange", "Port", "DNSName", "Malware", "Exploit", "HTTPRequest", "DNSRecord", "IP", "Service", "Host", "Vulnerability", "Flow", "AS", "Software"};

	private long ipToLong(String ipString)	{
		long ipLong = 0;
		long ip;
		String[] ipArray = ipString.split("\\.");
		for (int i = 3; i >= 0; i--) {
			ip = Long.parseLong(ipArray[3 - i]);
			ipLong |= ip << (i * 8);
		}
		
		return ipLong;
	}

	@Test 
	public void testVulnerabilityExploit() {

		System.out.println("[RUNNING] GraphConstructorTest.testVulnerabilityExploit()");

		String stix =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:metasploit-2e579a0a-0c44-4311-b6f0-a8fee86c3949\""+
			"    timestamp=\"2015-12-07T23:26:28.613Z\""+
			"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\""+
			"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Vulnerability and Malware Description</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>Metasploit</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:TTPs>"+
			"        <stix:TTP"+
			"            id=\"stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\">"+
			"            <ttp:Title>Exploit</ttp:Title>"+
			"            <ttp:Behavior>"+
			"                <ttp:Exploits>"+
			"                    <ttp:Exploit id=\"stucco:exploit-5b890dac-8005-48b1-a801-d1352898cd14\">"+
			"                        <ttp:Title>exploit/aix/rpc_cmsd_opcode21</ttp:Title>"+
			"                        <ttp:Description>This module exploits a buffer overflow vulnerability.</ttp:Description>"+
			"                        <ttp:Short_Description>AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow</ttp:Short_Description>"+
			"                    </ttp:Exploit>"+
			"                </ttp:Exploits>"+
			"            </ttp:Behavior>"+
			"            <ttp:Exploit_Targets>"+
			"                <ttp:Exploit_Target>"+
			"                    <stixCommon:Relationship>Exploits</stixCommon:Relationship>"+
			"                    <stixCommon:Exploit_Target"+
			"                        idref=\"Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760\""+
			"                        xmlns=\"\" xsi:type=\"et:ExploitTargetType\"/>"+
			"                </ttp:Exploit_Target>"+
			"            </ttp:Exploit_Targets>"+
			"            <ttp:Information_Source>"+
			"                <stixCommon:Contributing_Sources>"+
			"                    <stixCommon:Source>"+
			"                        <stixCommon:Identity>"+
			"                            <stixCommon:Name>Metasploit</stixCommon:Name>"+
			"                        </stixCommon:Identity>"+
			"                    </stixCommon:Source>"+
			"                </stixCommon:Contributing_Sources>"+
			"            </ttp:Information_Source>"+
			"        </stix:TTP>"+
			"    </stix:TTPs>"+
			"    <stix:Exploit_Targets>"+
			"        <stixCommon:Exploit_Target"+
			"            id=\"Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760\""+
			"            xmlns=\"\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\">"+
			"            <et:Title>Vulnerability</et:Title>"+
			"            <et:Vulnerability>"+
			"                <et:Description>CVE-2009-3699</et:Description>"+
			"                <et:CVE_ID>CVE-2009-3699</et:CVE_ID>"+
			"                <et:Source>Metasploit</et:Source>"+
			"            </et:Vulnerability>"+
			"        </stixCommon:Exploit_Target>"+
			"    </stix:Exploit_Targets>"+
			"</stix:STIX_Package>";

		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Exploit ...");
		Element sourceElement = stixElements.get("stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d");
		assertTrue(vertices.has("exploit/aix/rpc_cmsd_opcode21"));
		JSONObject vertex = vertices.getJSONObject("exploit/aix/rpc_cmsd_opcode21");
		assertEquals(vertex.getString("vertexType"), "Exploit");
		assertEquals(vertex.getString("name"), "exploit/aix/rpc_cmsd_opcode21");
		assertEquals(vertex.get("source").toString(), "[Metasploit]");
		assertEquals(vertex.get("description").toString(), "[This module exploits a buffer overflow vulnerability.]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		assertEquals(vertex.get("shortDescription").toString(), "[AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow]");
		
		System.out.println("Testing Vulnerability Vertex ... ");
		String id = "Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("CVE-2009-3699"));
		vertex = vertices.getJSONObject("CVE-2009-3699");
		assertEquals(vertex.getString("vertexType"), "Vulnerability");
		assertEquals(vertex.getString("name"), "CVE-2009-3699");
		assertEquals(vertex.get("source").toString(), "[Metasploit]");
		assertEquals(vertex.get("description").toString(), "[CVE-2009-3699]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");
		
		System.out.println("Testing Exploit -> Exploits -> Vulnerability Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("CVE-2009-3699") && 
				edge.getString("outVertID").equals("exploit/aix/rpc_cmsd_opcode21") && 
				edge.getString("relation").equals("Exploits")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}
	@Test 
	public void testMalwareIP() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testMalwareIP()");
		
		String stix =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:onedfourdotus-2260698e-056d-401a-a608-40a94bdf120b\""+
			"    timestamp=\"2015-12-08T19:04:57.617Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\""+
			"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>IP Addresses of SSH Scanners</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>1d4.us</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>1d4.us</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-1730444733\">"+
			"                <cybox:Description>103.36.125.189</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>103.36.125.189</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"    <stix:TTPs>"+
			"        <stix:TTP"+
			"            id=\"stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\">"+
			"            <ttp:Title>Malware</ttp:Title>"+
			"            <ttp:Behavior>"+
			"                <ttp:Malware>"+
			"                    <ttp:Malware_Instance id=\"stucco:malware-scanner\">"+
			"                        <ttp:Type>Scanner</ttp:Type>"+
			"                        <ttp:Name>Scanner</ttp:Name>"+
			"                        <ttp:Title>Scanner</ttp:Title>"+
			"                        <ttp:Description>Scanner</ttp:Description>"+
			"                    </ttp:Malware_Instance>"+
			"                </ttp:Malware>"+
			"            </ttp:Behavior>"+
			"            <ttp:Resources>"+
			"                <ttp:Infrastructure>"+
			"                    <ttp:Observable_Characterization"+
			"                        cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"                        <cybox:Observable idref=\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229\"/>"+
			"                    </ttp:Observable_Characterization>"+
			"                </ttp:Infrastructure>"+
			"            </ttp:Resources>"+
			"            <ttp:Information_Source>"+
			"                <stixCommon:Contributing_Sources>"+
			"                    <stixCommon:Source>"+
			"                        <stixCommon:Identity>"+
			"                            <stixCommon:Name>1d4.us</stixCommon:Name>"+
			"                        </stixCommon:Identity>"+
			"                    </stixCommon:Source>"+
			"                </stixCommon:Contributing_Sources>"+
			"            </ttp:Information_Source>"+
			"        </stix:TTP>"+
			"    </stix:TTPs>"+
			"</stix:STIX_Package>";	

		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Malware Vertex ... ");
		String id = "stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3";
		Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("Scanner"));
		JSONObject vertex = vertices.getJSONObject("Scanner");
		assertEquals(vertex.getString("vertexType"), "Malware");
		assertEquals(vertex.getString("name"), "Scanner");
		assertEquals(vertex.get("source").toString(), "[1d4.us]");
		assertEquals(vertex.get("description").toString(), "[Scanner]");
		
		System.out.println("Testing IP Vertex ... ");
		id = "Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("103.36.125.189"));
		vertex = vertices.getJSONObject("103.36.125.189");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "103.36.125.189");
		assertEquals(vertex.getLong("ipInt"), ipToLong("103.36.125.189"));
		assertEquals(vertex.get("source").toString(), "[1d4.us]");
		assertEquals(vertex.get("description").toString(), "[103.36.125.189]");
		
		JSONArray edges = graph.getJSONArray("edges");
		
		System.out.println("Testing Malware -> Uses_IP -> IP Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("103.36.125.189") && 
				edge.getString("outVertID").equals("Scanner") && 
				edge.getString("relation").equals("Uses_IP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testFlowAddressIpPort() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testFlowAddressIpPort()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:argus-65e89641-e5a2-4121-952b-c348445f139c\""+
			"    timestamp=\"2015-12-08T22:09:48.511Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:NetFlowObj=\"http://cybox.mitre.org/objects#NetworkFlowObject-2\""+
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\""+
			"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Network Flow Dataset</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>Argus</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-168430081\">"+
			"                <cybox:Description>10.10.10.1</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>10.10.10.1</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09\">"+
			"            <cybox:Title>Port</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:port-56867\">"+
			"                <cybox:Description>56867</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\">"+
			"                    <PortObj:Port_Value>56867</PortObj:Port_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-168430180\">"+
			"                <cybox:Description>10.10.10.100</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>10.10.10.100</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26\">"+
			"            <cybox:Title>Port</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:port-22\">"+
			"                <cybox:Description>22</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\">"+
			"                    <PortObj:Port_Value>22</PortObj:Port_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f\">"+
			"            <cybox:Title>Address</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:address-168430081_56867\">"+
			"                <cybox:Description>10.10.10.1, port 56867</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\">"+
			"                    <SocketAddressObj:IP_Address object_reference=\"stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489\"/>"+
			"                    <SocketAddressObj:Port object_reference=\"stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09\"/>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd\">"+
			"            <cybox:Title>Address</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:address-168430180_22\">"+
			"                <cybox:Description>10.10.10.100, port 22</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\">"+
			"                    <SocketAddressObj:IP_Address object_reference=\"stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a\"/>"+
			"                    <SocketAddressObj:Port object_reference=\"stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26\"/>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:flow-da6b7a73-6ed4-4d9a-b8dd-b770e2619ffb\">"+
			"            <cybox:Title>Flow</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>Argus</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:flow-168430081_56867-168430180_22\">"+
			"                <cybox:Description>10.10.10.1, port 56867 to 10.10.10.100, port 22</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetFlowObj:NetworkFlowObjectType\">"+
			"                    <cyboxCommon:Custom_Properties>"+
			"                        <cyboxCommon:Property name=\"TotBytes\">585</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"Flgs\"> e s</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"State\">REQ</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"StartTime\">1373553586.136399</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"Dir\">-&gt;</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"TotPkts\">8</cyboxCommon:Property>"+
			"                    </cyboxCommon:Custom_Properties>"+
			"                    <NetFlowObj:Network_Flow_Label>"+
			"                        <NetFlowObj:Src_Socket_Address object_reference=\"stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f\"/>"+
			"                        <NetFlowObj:Dest_Socket_Address object_reference=\"stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd\"/>"+
			"                        <NetFlowObj:IP_Protocol>6</NetFlowObj:IP_Protocol>"+
			"                    </NetFlowObj:Network_Flow_Label>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";

		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Flow Vertex ... ");
		String id = "stucco:flow-da6b7a73-6ed4-4d9a-b8dd-b770e2619ffb";
		Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("10.10.10.1:56867_through_10.10.10.100:22"));
		JSONObject vertex = vertices.getJSONObject("10.10.10.1:56867_through_10.10.10.100:22");
		assertEquals(vertex.getString("vertexType"), "Flow");
		assertEquals(vertex.getString("name"), "10.10.10.1:56867_through_10.10.10.100:22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1, port 56867 to 10.10.10.100, port 22]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	
		
		System.out.println("Testing (Source) Address Vertex ... ");
		id = "stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f";	
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("10.10.10.1:56867"));
		vertex = vertices.getJSONObject("10.10.10.1:56867");
		assertEquals(vertex.getString("vertexType"), "Address");
		assertEquals(vertex.getString("name"), "10.10.10.1:56867");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1, port 56867]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) Address Vertex ... ");
		id = "stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("10.10.10.100:22"));
		vertex = vertices.getJSONObject("10.10.10.100:22");
		assertEquals(vertex.getString("vertexType"), "Address");
		assertEquals(vertex.getString("name"), "10.10.10.100:22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.100, port 22]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Source) IP Vertex ... ");
		id = "stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("10.10.10.1"));
		vertex = vertices.getJSONObject("10.10.10.1");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "10.10.10.1");
		assertEquals(vertex.getLong("ipInt"), ipToLong("10.10.10.1"));
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) IP Vertex ... ");
		id = "stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("10.10.10.100"));
		vertex = vertices.getJSONObject("10.10.10.100");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "10.10.10.100");
		assertEquals(vertex.getLong("ipInt"), ipToLong("10.10.10.100"));
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.100]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Source) Port Vertex ... ");
		id = "stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("56867"));
		vertex = vertices.getJSONObject("56867");
		assertEquals(vertex.getString("vertexType"), "Port");
		assertEquals(vertex.getString("name"), "56867");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[56867]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) Port Vertex ... ");
		id = "stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("22"));
		vertex = vertices.getJSONObject("22");
		assertEquals(vertex.getString("vertexType"), "Port");
		assertEquals(vertex.getString("name"), "22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[22]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Flow -> Src_Socket_Address -> Address Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("10.10.10.1:56867") && 
				edge.getString("outVertID").equals("10.10.10.1:56867_through_10.10.10.100:22") && 
				edge.getString("relation").equals("Src_Socket_Address")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing Flow -> Dest_Socket_Address -> Address Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("10.10.10.100:22") && 
				edge.getString("outVertID").equals("10.10.10.1:56867_through_10.10.10.100:22") && 
				edge.getString("relation").equals("Dest_Socket_Address")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Source) Address -> Has_IP -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("10.10.10.1") && 
				edge.getString("outVertID").equals("10.10.10.1:56867") && 
				edge.getString("relation").equals("Has_IP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Destination) Address -> Has_IP -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("10.10.10.100") && 
				edge.getString("outVertID").equals("10.10.10.100:22") && 
				edge.getString("relation").equals("Has_IP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Source) Address -> Has_Port -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("56867") && 
				edge.getString("outVertID").equals("10.10.10.1:56867") && 
				edge.getString("relation").equals("Has_Port")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Destination) Address -> Has_Port -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("22") && 
				edge.getString("outVertID").equals("10.10.10.100:22") && 
				edge.getString("relation").equals("Has_Port")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

	}	

	@Test 
	public void testOrganizationAddressRangeAS() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testOrganizationAddressRangeAS()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:caida-3c9d71d7-3cc2-4bca-8d26-07e2121f9156\""+
			"    timestamp=\"2015-12-08T22:51:14.418Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:ASObj=\"http://cybox.mitre.org/objects#ASObject-1\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:WhoisObj=\"http://cybox.mitre.org/objects#WhoisObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>IP-AS Links Dataset</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>CAIDA</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95\">"+
			"            <cybox:Title>AddressRange</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>CAIDA</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:addressRange-1158921728-1158921983\">"+
			"                <cybox:Description>69.19.190.0 through 69.19.190.255</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value apply_condition=\"ANY\""+
			"                        condition=\"InclusiveBetween\" delimiter=\" - \">69.19.190.0 - 69.19.190.255</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f\">"+
			"            <cybox:Title>AS</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>CAIDA</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:as-o1comm_19864\">"+
			"                <cybox:Description>AS O1COMM has ASN 19864</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ASObj:ASObjectType\">"+
			"                    <ASObj:Number>19864</ASObj:Number>"+
			"                    <ASObj:Name>O1COMM</ASObj:Name>"+
			"                    <ASObj:Regional_Internet_Registry>ARIN</ASObj:Regional_Internet_Registry>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95\">"+
			"                        <cybox:Description>AS O1COMM with ASN 19864 contains IP address range 69.19.190.0 through 69.19.190.255</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>CAIDA</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Contains</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:organization-548c49e0-4a24-443d-80f6-ec6885bab598\">"+
			"            <cybox:Title>Organization</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>CAIDA</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:organization-o1.com\">"+
			"                <cybox:Description>Organization O1.com located in US has a range of IP addresses</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WhoisObj:WhoisObjectType\">"+
			"                    <WhoisObj:Registrants>"+
			"                        <WhoisObj:Registrant>"+
			"                            <WhoisObj:Address>US</WhoisObj:Address>"+
			"                            <WhoisObj:Organization>O1.com</WhoisObj:Organization>"+
			"                            <WhoisObj:Registrant_ID>01CO-ARIN</WhoisObj:Registrant_ID>"+
			"                        </WhoisObj:Registrant>"+
			"                    </WhoisObj:Registrants>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f\">"+
			"                        <cybox:Description>Organization O1.com has AS</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>CAIDA</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Has_AS</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Organization Vertex ... ");
		String id = "stucco:organization-548c49e0-4a24-443d-80f6-ec6885bab598";
		Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("O1.com"));
		JSONObject vertex = vertices.getJSONObject("O1.com");
		assertEquals(vertex.getString("vertexType"), "Organization");
		assertEquals(vertex.getString("name"), "O1.com");
		assertEquals(vertex.get("source").toString(), "[CAIDA]");
		assertEquals(vertex.get("description").toString(), "[Organization O1.com located in US has a range of IP addresses]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	
		
		System.out.println("Testing AS Vertex ... ");
		id = "stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("O1COMM"));
		vertex = vertices.getJSONObject("O1COMM");
		assertEquals(vertex.getString("vertexType"), "AS");
		assertEquals(vertex.getString("name"), "O1COMM");
		assertEquals(vertex.getString("number"), "19864");
		assertEquals(vertex.get("source").toString(), "[CAIDA]");
		assertEquals(vertex.get("description").toString(), "[AS O1COMM has ASN 19864]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing AddressRange Vertex ... ");
		id = "stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95";
		sourceElement = stixElements.get(id);
		assertTrue(vertices.has("69.19.190.0 - 69.19.190.255"));
		vertex = vertices.getJSONObject("69.19.190.0 - 69.19.190.255");
		assertEquals(vertex.getString("vertexType"), "AddressRange");
		assertEquals(vertex.getString("name"), "69.19.190.0 - 69.19.190.255");
		assertEquals(vertex.getString("startIP"), "69.19.190.0");
		assertEquals(vertex.getLong("startIPInt"), ipToLong("69.19.190.0"));
		assertEquals(vertex.getString("endIP"), "69.19.190.255");
		assertEquals(vertex.getLong("endIPInt"), ipToLong("69.19.190.255"));
		assertEquals(vertex.get("source").toString(), "[CAIDA]");
		assertEquals(vertex.get("description").toString(), "[69.19.190.0 through 69.19.190.255]");
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Organization -> Has_AS -> AS Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("O1COMM") && 
				edge.getString("outVertID").equals("O1.com") && 
				edge.getString("relation").equals("Has_AS")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing AS -> Contains -> AddressRange Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("69.19.190.0 - 69.19.190.255") && 
				edge.getString("outVertID").equals("O1COMM") && 
				edge.getString("relation").equals("Contains")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testSoftware() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testSoftware()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package id=\"stucco:cpe-de1f145f-1f52-4895-97bf-aa605cef2f3a\""+
			"    timestamp=\"2015-12-08T23:02:25.105Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Software Description</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>CPE</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:software-69a621f6-d22c-4d9c-a758-bc465dd8235b\">"+
			"            <cybox:Title>Software</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>CPE</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:software-cpe__a_1024cms_1024_cms_0.7\">"+
			"                <cybox:Description>1024cms.org 1024 CMS 0.7</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\">"+
			"                    <cyboxCommon:Custom_Properties>"+
			"                        <cyboxCommon:Property name=\"Part\">/a</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"NVD_ID\">121218</cyboxCommon:Property>"+
			"                    </cyboxCommon:Custom_Properties>"+
			"                    <ProductObj:Product>1024_cms</ProductObj:Product>"+
			"                    <ProductObj:Vendor>1024cms</ProductObj:Vendor>"+
			"                    <ProductObj:Version>0.7</ProductObj:Version>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Software Vertex ... ");
		String id = "stucco:software-69a621f6-d22c-4d9c-a758-bc465dd8235b";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("cpe:/a:1024cms:1024_cms:0.7:::");
		assertEquals(vertex.getString("vertexType"), "Software");
		assertEquals(vertex.getString("name"), "cpe:/a:1024cms:1024_cms:0.7:::");
		assertEquals(vertex.get("source").toString(), "[CPE]");
		assertEquals(vertex.get("description").toString(), "[1024cms.org 1024 CMS 0.7]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	}

	@Test 
	public void testDNSRecordIpDNSName() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testDNSRecordIpDNSName()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:dnsrecord-88a0833a-bd9f-4a23-ac84-2ec458f205a6\""+
			"    timestamp=\"2015-12-08T23:09:43.856Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\""+
			"    xmlns:DomainNameObj=\"http://cybox.mitre.org/objects#DomainNameObject-1\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>DNS Record</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>DNSRecord</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>DNSRecord</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-2161881588\">"+
			"                <cybox:Description>128.219.177.244</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>128.219.177.244</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>DNSRecord</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-1146571253\">"+
			"                <cybox:Description>68.87.73.245</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>68.87.73.245</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:ip-bd47ec2e-14a8-4126-8ae0-092b8276bf09\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>DNSRecord</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-1498369357\">"+
			"                <cybox:Description>89.79.77.77</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>89.79.77.77</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:dnsName-d64a70b3-6371-4fce-a0bf-24d902a3dc6c\">"+
			"            <cybox:Title>DNSName</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>DNSRecord</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:dnsName-dale-pc.ornl.gov\">"+
			"                <cybox:Description>DALE-PC.ORNL.GOV</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DomainNameObj:DomainNameObjectType\">"+
			"                    <DomainNameObj:Value>DALE-PC.ORNL.GOV</DomainNameObj:Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:dnsRecord-559dd80d-97b6-4c08-97eb-37001d2c59cb\">"+
			"            <cybox:Title>DNSRecord</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>DNSRecord</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:dnsRecord-00eaf8b8-704a-4a57-a06c-1ddab51a2319\">"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DNSRecordObj:DNSRecordObjectType\">"+
			"                    <DNSRecordObj:Description>Requested domain name DALE-PC.ORNL.GOV resolved to IP address 89.79.77.77</DNSRecordObj:Description>"+
			"                    <DNSRecordObj:Queried_Date>2015-07-12 00:00:27+00</DNSRecordObj:Queried_Date>"+
			"                    <DNSRecordObj:Domain_Name object_reference=\"stucco:dnsName-d64a70b3-6371-4fce-a0bf-24d902a3dc6c\"/>"+
			"                    <DNSRecordObj:IP_Address object_reference=\"stucco:ip-bd47ec2e-14a8-4126-8ae0-092b8276bf09\"/>"+
			"                    <DNSRecordObj:Entry_Type>1</DNSRecordObj:Entry_Type>"+
			"                    <DNSRecordObj:TTL>0</DNSRecordObj:TTL>"+
			"                    <DNSRecordObj:Flags>17</DNSRecordObj:Flags>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44\">"+
			"                        <cybox:Description>Requested IP.</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>DNSRequest</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Requested_By</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                    <cybox:Related_Object idref=\"stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63\">"+
			"                        <cybox:Description>Served IP request.</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>DNSRequest</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Served_By</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing DNSRecord ... ");
		String id = "stucco:dnsRecord-559dd80d-97b6-4c08-97eb-37001d2c59cb";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77");
		assertEquals(vertex.getString("vertexType"), "DNSRecord");
		assertEquals(vertex.getString("name"), "DALE-PC.ORNL.GOV_resolved_to_89.79.77.77");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[Requested domain name DALE-PC.ORNL.GOV resolved to IP address 89.79.77.77]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing IP ... ");
		id = "stucco:ip-bd47ec2e-14a8-4126-8ae0-092b8276bf09";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("89.79.77.77");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "89.79.77.77");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[89.79.77.77]");
		assertEquals(vertex.get("ipInt").toString(), "1498369357");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing IP ... ");
		id = "stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("128.219.177.244");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "128.219.177.244");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[128.219.177.244]");
		assertEquals(vertex.get("ipInt").toString(), "2161881588");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		System.out.println("Testing IP ... ");
		id = "stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("68.87.73.245");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "68.87.73.245");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[68.87.73.245]");
		assertEquals(vertex.get("ipInt").toString(), "1146571253");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		System.out.println("Testing DNSName ... ");
		id = "stucco:dnsName-d64a70b3-6371-4fce-a0bf-24d902a3dc6c";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("DALE-PC.ORNL.GOV");
		assertEquals(vertex.getString("vertexType"), "DNSName");
		assertEquals(vertex.getString("name"), "DALE-PC.ORNL.GOV");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[DALE-PC.ORNL.GOV]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing DNSRecord -> Requested_DNSName -> DNSName Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("DALE-PC.ORNL.GOV") && 
				edge.getString("outVertID").equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") &&
				edge.getString("relation").equals("Requested_DNSName")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Requested_IP -> Requested IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("89.79.77.77") && 
				edge.getString("outVertID").equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") &&
				edge.getString("relation").equals("Requested_IP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Served_By -> Server IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("128.219.177.244") && 
				edge.getString("outVertID").equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") &&
				edge.getString("relation").equals("Served_By")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Requested_By -> Requested by IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("68.87.73.245") && 
				edge.getString("outVertID").equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") &&
				edge.getString("relation").equals("Requested_By")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testServicePort() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testServicePort()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:servicelist-4cfb9e08-1b43-4a86-85f0-5b15478abf86\""+
			"    timestamp=\"2015-12-08T23:26:55.121Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\""+
			"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Service Description</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>service_list</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:port-cbd16bd3-38d6-49e5-86aa-39784a774c14\">"+
			"            <cybox:Title>Port</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>service_list</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:port-22\">"+
			"                <cybox:Description>22</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\">"+
			"                    <PortObj:Port_Value>22</PortObj:Port_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:service-f7791dd0-03d7-48f2-a323-c02c97008c4b\">"+
			"            <cybox:Title>Service</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>service_list</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:service-ssh\">"+
			"                <cybox:Description>The Secure Shell (SSH) Protocol</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProcessObj:ProcessObjectType\">"+
			"                    <cyboxCommon:Custom_Properties>"+
			"                        <cyboxCommon:Property name=\"Notes\">Defined TXT keys: u=&lt;username&gt; p=&lt;password&gt;</cyboxCommon:Property>"+
			"                        <cyboxCommon:Property name=\"Reference\">[RFC4251]</cyboxCommon:Property>"+
			"                    </cyboxCommon:Custom_Properties>"+
			"                    <ProcessObj:Name>ssh</ProcessObj:Name>"+
			"                    <ProcessObj:Port_List>"+
			"                        <ProcessObj:Port object_reference=\"stucco:port-cbd16bd3-38d6-49e5-86aa-39784a774c14\"/>"+
			"                    </ProcessObj:Port_List>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Service ... ");
		String id = "stucco:service-f7791dd0-03d7-48f2-a323-c02c97008c4b";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("ssh");
		assertEquals(vertex.getString("vertexType"), "Service");
		assertEquals(vertex.getString("name"), "ssh");
		assertEquals(vertex.get("source").toString(), "[service_list]");
		assertEquals(vertex.get("description").toString(), "[The Secure Shell (SSH) Protocol]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing Port ... ");
		id = "stucco:port-cbd16bd3-38d6-49e5-86aa-39784a774c14";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("22");
		assertEquals(vertex.getString("vertexType"), "Port");
		assertEquals(vertex.getString("name"), "22");
		assertEquals(vertex.get("source").toString(), "[service_list]");
		assertEquals(vertex.get("description").toString(), "[22]");
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Service -> Runs_On -> Port Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("22") && 
				edge.getString("outVertID").equals("ssh") &&
				edge.getString("relation").equals("Runs_On")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHTTPRequestIpPortDNSName() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testHTTPRequestIpPortDNSName()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:httprequest-c09a81e8-cc5b-4555-b5af-4ea7d2745298\""+
			"    timestamp=\"2015-12-08T23:31:41.595Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:DomainNameObj=\"http://cybox.mitre.org/objects#DomainNameObject-1\""+
			"    xmlns:HTTPSessionObj=\"http://cybox.mitre.org/objects#HTTPSessionObject-2\""+
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\""+
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>HTTPRequest</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>HTTPRequest</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:ip-86590b2c-5e14-4880-85ee-bc9d5c9a3302\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-2161848589\">"+
			"                <cybox:Description>128.219.49.13</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>128.219.49.13</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-918588136\">"+
			"                <cybox:Description>54.192.138.232</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>54.192.138.232</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:port-290e65ae-45df-431b-b051-6121201e9a6e\">"+
			"            <cybox:Title>Port</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:port-80\">"+
			"                <cybox:Description>80</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\">"+
			"                    <PortObj:Port_Value>80</PortObj:Port_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:dnsName-9e1fbf26-d46a-43cd-825a-145b31935344\">"+
			"            <cybox:Title>DNSName</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:dnsName-cdn455.telemetryverification.net\">"+
			"                <cybox:Description>cdn455.telemetryverification.net</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DomainNameObj:DomainNameObjectType\">"+
			"                    <DomainNameObj:Value>cdn455.telemetryverification.net</DomainNameObj:Value>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c\">"+
			"                        <cybox:Description>HTTP Server cdn455.telemetryverification.net resolved to 54.192.138.232</cybox:Description>"+
			"                        <cybox:Relationship>Resolved_To</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:httpRequest-59629f94-c963-4788-b897-b1e02bf92cab\">"+
			"            <cybox:Title>HTTPRequest</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:httpRequest-52137071-fce6-416a-adb0-40c4001c4c43\">"+
			"                <cybox:Description>HTTP request of URL /tv2n/vpaid/8bc5b7b</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HTTPSessionObj:HTTPSessionObjectType\">"+
			"                    <HTTPSessionObj:HTTP_Request_Response>"+
			"                        <HTTPSessionObj:HTTP_Client_Request>"+
			"                            <HTTPSessionObj:HTTP_Request_Line>"+
			"                                <HTTPSessionObj:HTTP_Method>GET</HTTPSessionObj:HTTP_Method>"+
			"                                <HTTPSessionObj:Value>/tv2n/vpaid/8bc5b7b</HTTPSessionObj:Value>"+
			"                                <HTTPSessionObj:Version>2</HTTPSessionObj:Version>"+
			"                            </HTTPSessionObj:HTTP_Request_Line>"+
			"                            <HTTPSessionObj:HTTP_Request_Header>"+
			"                                <HTTPSessionObj:Raw_Header>GET /tv2n/vpaid/8bc5b7b</HTTPSessionObj:Raw_Header>"+
			"                                <HTTPSessionObj:Parsed_Header>"+
			"                                    <HTTPSessionObj:Accept_Language>en-US,en;q=0.8</HTTPSessionObj:Accept_Language>"+
			"                                    <HTTPSessionObj:Content_Length>846</HTTPSessionObj:Content_Length>"+
			"                                    <HTTPSessionObj:Date>2015-09-09 00:03:09+00</HTTPSessionObj:Date>"+
			"                                    <HTTPSessionObj:From object_reference=\"stucco:ip-86590b2c-5e14-4880-85ee-bc9d5c9a3302\"/>"+
			"                                    <HTTPSessionObj:Host>"+
			"                                    <HTTPSessionObj:Domain_Name object_reference=\"stucco:dnsName-9e1fbf26-d46a-43cd-825a-145b31935344\"/>"+
			"                                    <HTTPSessionObj:Port object_reference=\"stucco:port-290e65ae-45df-431b-b051-6121201e9a6e\"/>"+
			"                                    </HTTPSessionObj:Host>"+
			"                                    <HTTPSessionObj:Referer>"+
			"                                    <URIObj:Value>http://portal.tds.net/?inc=4</URIObj:Value>"+
			"                                    </HTTPSessionObj:Referer>"+
			"                                    <HTTPSessionObj:User_Agent>Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36</HTTPSessionObj:User_Agent>"+
			"                                </HTTPSessionObj:Parsed_Header>"+
			"                            </HTTPSessionObj:HTTP_Request_Header>"+
			"                        </HTTPSessionObj:HTTP_Client_Request>"+
			"                    </HTTPSessionObj:HTTP_Request_Response>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing HTTPRequest ... ");
		String id = "stucco:httpRequest-59629f94-c963-4788-b897-b1e02bf92cab";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("/tv2n/vpaid/8bc5b7b");
		assertEquals(vertex.getString("vertexType"), "HTTPRequest");
		assertEquals(vertex.getString("name"), "/tv2n/vpaid/8bc5b7b");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[HTTP request of URL /tv2n/vpaid/8bc5b7b]");

		System.out.println("Testing IP ... ");
		id = "stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("54.192.138.232");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "54.192.138.232");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[54.192.138.232]");
		assertEquals(vertex.get("ipInt").toString(), "918588136");

		System.out.println("Testing IP ... ");
		id = "stucco:ip-86590b2c-5e14-4880-85ee-bc9d5c9a3302";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("128.219.49.13");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "128.219.49.13");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[128.219.49.13]");
		assertEquals(vertex.get("ipInt").toString(), "2161848589");

		System.out.println("Testing DNSName ... ");
		id = "stucco:dnsName-9e1fbf26-d46a-43cd-825a-145b31935344";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("cdn455.telemetryverification.net");
		assertEquals(vertex.getString("vertexType"), "DNSName");
		assertEquals(vertex.getString("name"), "cdn455.telemetryverification.net");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[cdn455.telemetryverification.net]");

		System.out.println("Testing Port ... ");
		id = "stucco:port-290e65ae-45df-431b-b051-6121201e9a6e";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("80");
		assertEquals(vertex.getString("vertexType"), "Port");
		assertEquals(vertex.getString("name"), "80");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[80]");

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing HTTPRequest -> IP Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("128.219.49.13") && 
				edge.getString("outVertID").equals("/tv2n/vpaid/8bc5b7b") &&
				edge.getString("relation").equals("Requested_By")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing HTTPRequest -> Served_On -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("80") && 
				edge.getString("outVertID").equals("/tv2n/vpaid/8bc5b7b") &&
				edge.getString("relation").equals("Served_On")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing HTTPRequest -> Served_By -> DNSName Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("cdn455.telemetryverification.net") && 
				edge.getString("outVertID").equals("/tv2n/vpaid/8bc5b7b") &&
				edge.getString("relation").equals("Served_By")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHostSoftware() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testHostSoftware()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:packagelist-a3e4878b-b27d-46ee-9fe4-2e0febaec3ae\""+
			"    timestamp=\"2015-12-08T23:36:50.780Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:HostnameObj=\"http://cybox.mitre.org/objects#HostnameObject-1\""+
			"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Software Description</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>PackageList</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02\">"+
			"            <cybox:Title>Software</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>PackageList</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:software-ftp_0.17-25\">"+
			"                <cybox:Description>ftp version 0.17-25</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\">"+
			"                    <ProductObj:Product>ftp</ProductObj:Product>"+
			"                    <ProductObj:Version>0.17-25</ProductObj:Version>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:hostname-e11a469e-a66a-42b5-835f-d6599cc592a6\">"+
			"            <cybox:Title>Host</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>PackageList</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:hostname-stucco1\">"+
			"                <cybox:Description>stucco1</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HostnameObj:HostnameObjectType\">"+
			"                    <HostnameObj:Hostname_Value>stucco1</HostnameObj:Hostname_Value>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02\">"+
			"                        <cybox:Description>stucco1 runs ftp_0.17-25</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>PackageList</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Runs</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Software ... ");
		String id = "stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("cpe:::ftp:0.17-25:::");
		assertEquals(vertex.getString("vertexType"), "Software");
		assertEquals(vertex.getString("name"), "cpe:::ftp:0.17-25:::");
		assertEquals(vertex.get("source").toString(), "[PackageList]");
		assertEquals(vertex.get("description").toString(), "[ftp version 0.17-25]");
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-e11a469e-a66a-42b5-835f-d6599cc592a6";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco1");
		assertEquals(vertex.getString("vertexType"), "Host");
		assertEquals(vertex.getString("name"), "stucco1");
		assertEquals(vertex.get("source").toString(), "[PackageList]");
		assertEquals(vertex.get("description").toString(), "[stucco1]");

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Host -> Runs -> Software Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("cpe:::ftp:0.17-25:::") && 
				edge.getString("outVertID").equals("stucco1") &&
				edge.getString("relation").equals("Runs")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHostSoftwareAccountIp() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testHostSoftwareAccountIp()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:loginevent-0674bfe0-7622-4c9c-863f-d1fe4e9c05a3\""+
			"    timestamp=\"2015-12-08T23:42:11.823Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
			"    xmlns:AccountObj=\"http://cybox.mitre.org/objects#AccountObject-2\""+
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\""+
			"    xmlns:HostnameObj=\"http://cybox.mitre.org/objects#HostnameObject-1\""+
			"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\""+
			"    xmlns:UserAccountObj=\"http://cybox.mitre.org/objects#UserAccountObject-2\""+
			"    xmlns:UserSessionObj=\"http://cybox.mitre.org/objects#UserSessionObject-2\""+
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Login Event</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>LoginEvent</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"stucco:software-cc2b74cc-7cf2-4383-be29-a41f67332aca\">"+
			"            <cybox:Title>Software</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:software-sshd\">"+
			"                <cybox:Description>sshd</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\">"+
			"                    <ProductObj:Product>sshd</ProductObj:Product>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-3232238091\">"+
			"                <cybox:Description>192.168.10.11</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\""+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value>192.168.10.11</AddressObj:Address_Value>"+
			"                </cybox:Properties>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:account-c42d3219-bb0a-486e-b144-e3c8887a504e\">"+
			"            <cybox:Title>Account</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:account-stuccouser\">"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UserAccountObj:UserAccountObjectType\">"+
			"                    <AccountObj:Description>StuccoUser</AccountObj:Description>"+
			"                    <UserAccountObj:Username>StuccoUser</UserAccountObj:Username>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:hostname-67ae4885-0914-429c-ac61-fa8f1932ec53\">"+
			"                        <cybox:State>Accepted</cybox:State>"+
			"                        <cybox:Description>StuccoUser logs in to StuccoHost</cybox:Description>"+
			"                        <cybox:Properties"+
			"                            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UserSessionObj:UserSessionObjectType\">"+
			"                            <UserSessionObj:Login_Time>Sep 24 15:11:03</UserSessionObj:Login_Time>"+
			"                        </cybox:Properties>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Logs_In_To</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                    <cybox:Related_Object idref=\"stucco:hostname-01b000b8-9326-43d5-b94a-60f299c9dd35\">"+
			"                        <cybox:State>Accepted</cybox:State>"+
			"                        <cybox:Description>StuccoUser logs in from host at 192.168.10.11</cybox:Description>"+
			"                        <cybox:Properties"+
			"                            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UserSessionObj:UserSessionObjectType\">"+
			"                            <UserSessionObj:Login_Time>Sep 24 15:11:03</UserSessionObj:Login_Time>"+
			"                        </cybox:Properties>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Logs_In_From</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:hostname-67ae4885-0914-429c-ac61-fa8f1932ec53\">"+
			"            <cybox:Title>Host</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:hostname-stuccohost\">"+
			"                <cybox:Description>StuccoHost</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HostnameObj:HostnameObjectType\">"+
			"                    <HostnameObj:Hostname_Value>StuccoHost</HostnameObj:Hostname_Value>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:software-cc2b74cc-7cf2-4383-be29-a41f67332aca\">"+
			"                        <cybox:Description>StuccoHost runs sshd</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Runs</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"        <cybox:Observable id=\"stucco:hostname-01b000b8-9326-43d5-b94a-60f299c9dd35\">"+
			"            <cybox:Title>Host</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:hostname-host_at_192.168.10.11\">"+
			"                <cybox:Description>host at 192.168.10.11</cybox:Description>"+
			"                <cybox:Properties"+
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HostnameObj:HostnameObjectType\">"+
			"                    <HostnameObj:Hostname_Value>host_at_192.168.10.11</HostnameObj:Hostname_Value>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\">"+
			"                        <cybox:Description>host_at_192.168.10.11 resolved to IP 192.168.10.11</cybox:Description>"+
			"                        <cybox:Discovery_Method>"+
			"                            <cyboxCommon:Information_Source_Type>LoginEvent</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Resolved_To</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Account ... ");
		String id = "stucco:account-c42d3219-bb0a-486e-b144-e3c8887a504e";
		Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("StuccoUser");
		assertEquals(vertex.getString("vertexType"), "Account");
		assertEquals(vertex.getString("name"), "StuccoUser");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertEquals(vertex.get("description").toString(), "[StuccoUser]");
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-01b000b8-9326-43d5-b94a-60f299c9dd35";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("host_at_192.168.10.11");
		assertEquals(vertex.getString("vertexType"), "Host");
		assertEquals(vertex.getString("name"), "host_at_192.168.10.11");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertEquals(vertex.get("description").toString(), "[host at 192.168.10.11]");
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-67ae4885-0914-429c-ac61-fa8f1932ec53";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("StuccoHost");
		assertEquals(vertex.getString("vertexType"), "Host");
		assertEquals(vertex.getString("name"), "StuccoHost");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertEquals(vertex.get("description").toString(), "[StuccoHost]");
		
		System.out.println("Testing Software ... ");
		id = "stucco:software-cc2b74cc-7cf2-4383-be29-a41f67332aca";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("cpe:::sshd::::");
		assertEquals(vertex.getString("vertexType"), "Software");
		assertEquals(vertex.getString("name"), "cpe:::sshd::::");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertEquals(vertex.get("description").toString(), "[sshd]");

		System.out.println("Testing IP ... ");
		id = "stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241";
		sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("192.168.10.11");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "192.168.10.11");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertEquals(vertex.get("description").toString(), "[192.168.10.11]");
		assertEquals(vertex.get("ipInt").toString(), "3232238091");

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Account -> Logs_In_From -> Host Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("host_at_192.168.10.11") && 
				edge.getString("outVertID").equals("StuccoUser") &&
				edge.getString("relation").equals("Logs_In_From")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Account -> Logs_In_To -> Host Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("StuccoHost") && 
				edge.getString("outVertID").equals("StuccoUser") &&
				edge.getString("relation").equals("Logs_In_To")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Host -> Runs -> Software Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("cpe:::sshd::::") && 
				edge.getString("outVertID").equals("StuccoHost") &&
				edge.getString("relation").equals("Runs")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Host -> Resolved_To -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("192.168.10.11") && 
				edge.getString("outVertID").equals("host_at_192.168.10.11") &&
				edge.getString("relation").equals("Resolved_To")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testVulnerabilityWithSolution() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testVulnerabilityWithSolution()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:bugtraq-67d2ef28-9edb-4031-9867-ff502313590a\""+
			"    timestamp=\"2015-12-14T19:38:02.569Z\""+
			"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\""+
			"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\">"+
			"    <stix:STIX_Header>"+
			"        <stix:Title>Vulnerability Description</stix:Title>"+
			"        <stix:Information_Source>"+
			"            <stixCommon:Identity>"+
			"                <stixCommon:Name>Bugtraq</stixCommon:Name>"+
			"            </stixCommon:Identity>"+
			"        </stix:Information_Source>"+
			"    </stix:STIX_Header>"+
			"    <stix:Exploit_Targets>"+
			"        <stixCommon:Exploit_Target"+
			"            id=\"stucco:vulnerability-b73ca23e-66d6-4fd7-89b4-30859796b38e\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\">"+
			"            <et:Title>Vulnerability</et:Title>"+
			"            <et:Vulnerability>"+
			"                <et:Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.</et:Description>"+
			"                <et:Short_Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities</et:Short_Description>"+
			"                <et:CVE_ID>CVE-2015-2098</et:CVE_ID>"+
			"                <et:OSVDB_ID>72838</et:OSVDB_ID>"+
			"                <et:Source>Bugtraq</et:Source>"+
			"                <et:Published_DateTime>2015-03-27T00:00:00.000-04:00</et:Published_DateTime>"+
			"                <et:References>"+
			"                    <stixCommon:Reference>http://support.microsoft.com/kb/240797</stixCommon:Reference>"+
			"                    <stixCommon:Reference>Second</stixCommon:Reference>"+
			"                    <stixCommon:Reference>Third</stixCommon:Reference>"+
			"                </et:References>"+
			"            </et:Vulnerability>"+
			"            <et:Potential_COAs>"+
			"                <et:Potential_COA>"+
			"                    <stixCommon:Course_Of_Action"+
			"                        idref=\"stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b\" xsi:type=\"coa:CourseOfActionType\"/>"+
			"                </et:Potential_COA>"+
			"            </et:Potential_COAs>"+
			"        </stixCommon:Exploit_Target>"+
			"    </stix:Exploit_Targets>"+
			"    <stix:Courses_Of_Action>"+
			"        <stix:Course_Of_Action"+
			"            id=\"stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"coa:CourseOfActionType\">"+
			"            <coa:Title>Vulnerability</coa:Title>"+
			"            <coa:Description>Solution: Currently, we are not aware of any vendor-supplied patches. If you feel we are in error or are aware of more recent information, please mail us at: vuldb@securityfocus.com.</coa:Description>"+
			"            <coa:Information_Source>"+
			"                <stixCommon:Contributing_Sources>"+
			"                    <stixCommon:Source>"+
			"                        <stixCommon:Identity>"+
			"                            <stixCommon:Name>Bugtraq</stixCommon:Name>"+
			"                        </stixCommon:Identity>"+
			"                    </stixCommon:Source>"+
			"                </stixCommon:Contributing_Sources>"+
			"            </coa:Information_Source>"+
			"        </stix:Course_Of_Action>"+
			"    </stix:Courses_Of_Action>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(preprocessSTIX.validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Vulnerability Vertex ... ");
		JSONObject vertex = vertices.getJSONObject("CVE-2015-2098");
		assertEquals(vertex.getString("vertexType"), "Vulnerability");
		assertEquals(vertex.getString("name"), "CVE-2015-2098");
		assertEquals(vertex.get("source").toString(), "[Bugtraq]");
		assertEquals(vertex.get("description").toString(), "[WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.]");
		assertEquals(vertex.get("shortDescription").toString(), "[WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities]");
		assertEquals(vertex.get("publishedDate"), "2015-03-27T00:00:00.000-04:00");
		String id = "stucco:vulnerability-b73ca23e-66d6-4fd7-89b4-30859796b38e";
		Element sourceElement = stixElements.get(id);
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing Course_Of_Action Vertex ... ");
		vertex = vertices.getJSONObject("stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b");
		assertEquals(vertex.getString("vertexType"), "Course_Of_Action");
		assertEquals(vertex.getString("name"), "stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b");
		assertEquals(vertex.get("description").toString(), "[\"Solution: Currently, we are not aware of any vendor-supplied patches. If you feel we are in error or are aware of more recent information, please mail us at: vuldb@securityfocus.com.\"]");
		id = "stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b";
		sourceElement = stixElements.get(id);
		assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Vulnerability -> PotentialCOA -> Course_Of_Action Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals("stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b") && 
				edge.getString("outVertID").equals("CVE-2015-2098") &&
				edge.getString("relation").equals("PotentialCOA")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testAllStixElements() {
		
		System.out.println("[RUNNING] GraphConstructorTest.testAllStixElements()");
		try {	
			String stix = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
				"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\""+
				"    xmlns:campaign=\"http://stix.mitre.org/Campaign-1\""+
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\""+
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\""+
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\""+
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\""+
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\""+
				"    xmlns:ta=\"http://stix.mitre.org/ThreatActor-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">"+
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
				"        <cybox:Observable"+
				"            id=\"stucco:observable-bb95c949-7720-4b16-a491-93e0453b2785\" xmlns:stucco=\"gov.ornl.stucco\">"+
				"            <cybox:Title>Observable</cybox:Title>"+
				"        </cybox:Observable>"+
				"    </stix:Observables>"+
				"    <stix:Indicators>"+
				"        <stix:Indicator"+
				"            id=\"stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca\""+
				"            xmlns:stucco=\"gov.ornl.stucco\""+
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\">"+
				"            <indicator:Title>Indicator</indicator:Title>"+
				"            <indicator:Description>Indicator description</indicator:Description>"+
				"            <indicator:Observable idref=\"stucco:observable-bb95c949-7720-4b16-a491-93e0453b2785\"/>"+
				"            <indicator:Indicated_TTP>"+
				"                <stixCommon:TTP"+
				"                    id=\"stucco:ttp-8da79cbe-750d-4426-b960-baf8e67ec714\" xsi:type=\"ttp:TTPType\">"+
				"                    <ttp:Title>TTP</ttp:Title>"+
				"                </stixCommon:TTP>"+
				"            </indicator:Indicated_TTP>"+
				"            <indicator:Suggested_COAs>"+
				"                <indicator:Suggested_COA>"+
				"                    <stixCommon:Course_Of_Action"+
				"                        id=\"stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7\" xsi:type=\"coa:CourseOfActionType\">"+
				"                        <coa:Title>Course_Of_Action</coa:Title>"+
				"                        <coa:Description>Course_Of_Action description</coa:Description>"+
				"                        <coa:Information_Source>"+
				"                            <stixCommon:Identity>"+
				"                                <stixCommon:Name>Source One</stixCommon:Name>"+
				"                            </stixCommon:Identity>"+
				"                            <stixCommon:Contributing_Sources>"+
				"                                <stixCommon:Source>"+
				"                                    <stixCommon:Identity>"+
				"                                    <stixCommon:Name>Source Two</stixCommon:Name>"+
				"                                    </stixCommon:Identity>"+
				"                                </stixCommon:Source>"+
				"                            </stixCommon:Contributing_Sources>"+
				"                        </coa:Information_Source>"+
				"                    </stixCommon:Course_Of_Action>"+
				"                </indicator:Suggested_COA>"+
				"            </indicator:Suggested_COAs>"+
				"            <indicator:Related_Campaigns>"+
				"                <indicator:Related_Campaign>"+
				"                    <stixCommon:Campaign idref=\"stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c\"/>"+
				"                </indicator:Related_Campaign>"+
				"            </indicator:Related_Campaigns>"+
				"            <indicator:Producer>"+
				"                <stixCommon:Identity>"+
				"                    <stixCommon:Name>Source One</stixCommon:Name>"+
				"                </stixCommon:Identity>"+
				"                <stixCommon:Contributing_Sources>"+
				"                    <stixCommon:Source>"+
				"                        <stixCommon:Identity>"+
				"                            <stixCommon:Name>Source Two</stixCommon:Name>"+
				"                        </stixCommon:Identity>"+
				"                    </stixCommon:Source>"+
				"                </stixCommon:Contributing_Sources>"+
				"            </indicator:Producer>"+
				"        </stix:Indicator>"+
				"    </stix:Indicators>"+
				"    <stix:Exploit_Targets>"+
				"        <stixCommon:Exploit_Target"+
				"            id=\"stucco:et-52962ed3-1c7f-4cac-bedb-d49bb429b625\""+
				"            xmlns:stucco=\"gov.ornl.stucco\""+
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\">"+
				"            <et:Title>Exploit_Target</et:Title>"+
				"            <et:Weakness>"+
				"                <et:Description>Description of this weakness</et:Description>"+
				"                <et:CWE_ID>CWE-93487297</et:CWE_ID>"+
				"            </et:Weakness>"+
				"            <et:Potential_COAs>"+
				"                <et:Potential_COA>"+
				"                    <stixCommon:Course_Of_Action"+
				"                        idref=\"stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7\" xsi:type=\"coa:CourseOfActionType\"/>"+
				"                </et:Potential_COA>"+
				"            </et:Potential_COAs>"+
				"            <et:Information_Source>"+
				"                <stixCommon:Identity>"+
				"                    <stixCommon:Name>Source One</stixCommon:Name>"+
				"                </stixCommon:Identity>"+
				"                <stixCommon:Contributing_Sources>"+
				"                    <stixCommon:Source>"+
				"                        <stixCommon:Identity>"+
				"                            <stixCommon:Name>Source Two</stixCommon:Name>"+
				"                        </stixCommon:Identity>"+
				"                    </stixCommon:Source>"+
				"                </stixCommon:Contributing_Sources>"+
				"            </et:Information_Source>"+
				"        </stixCommon:Exploit_Target>"+
				"    </stix:Exploit_Targets>"+
				"    <stix:Campaigns>"+
				"        <stix:Campaign"+
				"            id=\"stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c\""+
				"            xmlns:stucco=\"gov.ornl.stucco\""+
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"campaign:CampaignType\">"+
				"            <campaign:Title>Campaign</campaign:Title>"+
				"            <campaign:Description>Campaign description</campaign:Description>"+
				"            <campaign:Names>"+
				"                <campaign:Name>Campaigns Name</campaign:Name>"+
				"            </campaign:Names>"+
				"            <campaign:Attribution>"+
				"                <campaign:Attributed_Threat_Actor>"+
				"                    <stixCommon:Threat_Actor"+
				"                        id=\"stucco:threat-9f055e12-d799-47d8-84a5-f018ee1ccb99\" xsi:type=\"ta:ThreatActorType\">"+
				"                        <ta:Title>Threat_Actor</ta:Title>"+
				"                        <ta:Identity>"+
				"                            <stixCommon:Name>Actor's name</stixCommon:Name>"+
				"                            <stixCommon:Related_Identities>"+
				"                                <stixCommon:Related_Identity>"+
				"                                    <stixCommon:Identity>"+
				"                                    <stixCommon:Name>Related Name</stixCommon:Name>"+
				"                                    </stixCommon:Identity>"+
				"                                </stixCommon:Related_Identity>"+
				"                            </stixCommon:Related_Identities>"+
				"                        </ta:Identity>"+
				"                    </stixCommon:Threat_Actor>"+
				"                </campaign:Attributed_Threat_Actor>"+
				"            </campaign:Attribution>"+
				"            <campaign:Information_Source>"+
				"                <stixCommon:Identity>"+
				"                    <stixCommon:Name>Source One</stixCommon:Name>"+
				"                </stixCommon:Identity>"+
				"                <stixCommon:Contributing_Sources>"+
				"                    <stixCommon:Source>"+
				"                        <stixCommon:Identity>"+
				"                            <stixCommon:Name>Source Two</stixCommon:Name>"+
				"                        </stixCommon:Identity>"+
				"                    </stixCommon:Source>"+
				"                </stixCommon:Contributing_Sources>"+
				"            </campaign:Information_Source>"+
				"        </stix:Campaign>"+
				"    </stix:Campaigns>"+
				"</stix:STIX_Package>";
			
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			STIXPackage pack = new STIXPackage().fromXMLString(stix);
			assertTrue(preprocessSTIX.validate(pack));
			GraphConstructor graphConstructor = new GraphConstructor();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			JSONObject vertices = graph.getJSONObject("vertices");

			System.out.println("Testing Indicator Vertex ... ");
			JSONObject vertex = vertices.getJSONObject("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca");
			assertEquals(vertex.getString("vertexType"), "Indicator");
			assertEquals(vertex.getString("name"), "stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca");
			assertEquals(vertex.get("description").toString(), "[\"Indicator description\"]");
			assertTrue(vertex.has("sourceDocument"));
			String sourceDocument = vertex.getString("sourceDocument");
			Indicator indicator = new Indicator().fromXMLString(sourceDocument);
			assertTrue(indicator.validate());
			
			System.out.println("Testing Observable Vertex ... ");
			vertex = vertices.getJSONObject("stucco:observable-bb95c949-7720-4b16-a491-93e0453b2785");
			assertEquals(vertex.getString("vertexType"), "Observable");
			assertEquals(vertex.getString("name"), "stucco:observable-bb95c949-7720-4b16-a491-93e0453b2785");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			Observable observable = new Observable().fromXMLString(sourceDocument);
			assertTrue(observable.validate());
			
			System.out.println("Testing TTP Vertex ... ");
			vertex = vertices.getJSONObject("stucco:ttp-8da79cbe-750d-4426-b960-baf8e67ec714");
			assertEquals(vertex.getString("vertexType"), "TTP");
			assertEquals(vertex.getString("name"), "stucco:ttp-8da79cbe-750d-4426-b960-baf8e67ec714");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			TTP ttp = new TTP().fromXMLString(sourceDocument);
			assertTrue(ttp.validate());

			System.out.println("Testing Course_Of_Action Vertex ... ");
			vertex = vertices.getJSONObject("stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7");
			assertEquals(vertex.getString("vertexType"), "Course_Of_Action");
			assertEquals(vertex.getString("name"), "stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7");
			assertEquals(vertex.get("description").toString(), "[\"Course_Of_Action description\"]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			CourseOfAction coa = new CourseOfAction().fromXMLString(sourceDocument);
			assertTrue(coa.validate());
			
			System.out.println("Testing Exploit_Target Vertex ... ");
			vertex = vertices.getJSONObject("stucco:et-52962ed3-1c7f-4cac-bedb-d49bb429b625");
			assertEquals(vertex.getString("vertexType"), "Exploit_Target");
			assertEquals(vertex.getString("name"), "stucco:et-52962ed3-1c7f-4cac-bedb-d49bb429b625");
			assertEquals(vertex.get("description").toString(), "[\"Description of this weakness\"]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			ExploitTarget et = new ExploitTarget().fromXMLString(sourceDocument);
			assertTrue(et.validate());
			
			System.out.println("Testing Campaign Vertex ... ");
			vertex = vertices.getJSONObject("stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c");
			assertEquals(vertex.getString("vertexType"), "Campaign");
			assertEquals(vertex.getString("name"), "stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c");
			assertEquals(vertex.get("description").toString(), "[\"Campaign description\"]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			Campaign campaign = new Campaign().fromXMLString(sourceDocument);
			assertTrue(campaign.validate());
			
			System.out.println("Testing Threat_Actor Vertex ... ");
			vertex = vertices.getJSONObject("stucco:threat-9f055e12-d799-47d8-84a5-f018ee1ccb99");
			assertEquals(vertex.getString("vertexType"), "Threat_Actor");
			assertEquals(vertex.getString("name"), "stucco:threat-9f055e12-d799-47d8-84a5-f018ee1ccb99");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			ThreatActor ta = new ThreatActor().fromXMLString(sourceDocument);
			assertTrue(ta.validate());

			JSONArray edges = graph.getJSONArray("edges");

			System.out.println("Testing Indicator -> IndicatedTTP -> TTP...");
			boolean edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:ttp-8da79cbe-750d-4426-b960-baf8e67ec714") && 
					edge.getString("outVertID").equals("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca") &&
					edge.getString("relation").equals("IndicatedTTP")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

			System.out.println("Testing Indicator -> SuggestedCOA -> Course_Of_Action...");
			edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7") && 
					edge.getString("outVertID").equals("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca") &&
					edge.getString("relation").equals("SuggestedCOA")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

			System.out.println("Testing Indicator -> RelatedCampaign -> Campaign...");
			edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c") && 
					edge.getString("outVertID").equals("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca") &&
					edge.getString("relation").equals("RelatedCampaign")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

			System.out.println("Testing Indicator -> Observable -> Observable ..");
			edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:observable-bb95c949-7720-4b16-a491-93e0453b2785") && 
					edge.getString("outVertID").equals("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca") &&
					edge.getString("relation").equals("Observable")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

			System.out.println("Testing Exploit_Target -> PotentialCOA -> Course_Of_Action...");
			edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:coa-ba3d4963-caa5-4f65-b224-8f0d5ab38aa7") && 
					edge.getString("outVertID").equals("stucco:et-52962ed3-1c7f-4cac-bedb-d49bb429b625") &&
					edge.getString("relation").equals("PotentialCOA")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

			System.out.println("Testing Threat_Actor -> Attribution -> Threat_Actor...");
			edgeExists = false;
			for (int i = 0; i < edges.length(); i++) {
				JSONObject edge = edges.getJSONObject(i);
				if (edge.getString("inVertID").equals("stucco:threat-9f055e12-d799-47d8-84a5-f018ee1ccb99") && 
					edge.getString("outVertID").equals("stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c") &&
					edge.getString("relation").equals("Attribution")) {
					edgeExists = true;
					break;
				}
			}
			assertTrue(edgeExists);

		} catch (SAXException e) {
			e.printStackTrace();
		}
	}
}
