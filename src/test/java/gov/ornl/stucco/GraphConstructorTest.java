package gov.ornl.stucco;

import gov.ornl.stucco.preprocessors.PreprocessSTIX;
import gov.ornl.stucco.preprocessors.PreprocessSTIX.Vertex;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;

import java.io.IOException; 

import java.nio.file.Files;
import java.nio.file.Paths;
 
import org.json.JSONObject;
import org.json.JSONArray; 

import org.jdom2.output.XMLOutputter;  
import org.jdom2.output.Format;
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

	public void printElement(Element element) {
		XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
		System.out.println(outputter.outputString(element));
	}

	private boolean validate(Map<String, Vertex> vertices) {
		boolean valid = true;
		try {
		  for (String id : vertices.keySet()) {
		    PreprocessSTIX.Vertex v = vertices.get(id);
		    String xml = v.xml;
		    if (v.type.equals("Observable")) {
		      Observable ob = new Observable().fromXMLString(xml);
		      if (!ob.validate()) {
		      	valid = false;
		      	System.out.println(ob.toXMLString(true));
		      }
		      // System.out.println(ob.validate());
		    } else if (v.type.equals("Indicator")) {
		      Indicator ob = new Indicator().fromXMLString(xml);
		      if (!ob.validate()) {
		      	System.out.println(ob.toXMLString(true));
		      	valid = false;
		      }
		      // System.out.println(ob.validate());
		    } else if (v.type.equals("Incident")) {
		      Incident ob = new Incident().fromXMLString(xml);
		      if (!ob.validate()) {
		      	System.out.println(ob.toXMLString(true));
		      	valid = false;
		      }
		      //System.out.println(ob.validate());
		    } else if (v.type.equals("TTP")) {
		    	TTP ttp = new TTP().fromXMLString(xml);
		      if (!ttp.validate()) {
		      	System.out.println(ttp.toXMLString(true));
		      	valid = false;
		      }
		    	//System.out.println(ttp.validate());
		    } else if (v.type.equals("Campaign")) {
		    	Campaign camp = new Campaign().fromXMLString(xml);
		      if (!camp.validate()) {
		      	System.out.println(camp.toXMLString(true));
		      	valid = false;
		      }
		    	// System.out.println(camp.validate());
		    } else if (v.type.equals("Threat_Actor")) {
		    	ThreatActor ta = new ThreatActor().fromXMLString(xml);
		      if (!ta.validate()) {
		      	System.out.println(ta.toXMLString(true));
		      	valid = false;
		      }
		    	// System.out.println(ta.validate());
		    } else if (v.type.equals("Exploit_Target")) {
		    	ExploitTarget et = new ExploitTarget().fromXMLString(xml);
		      if (!et.validate()) {
		      	System.out.println(et.toXMLString(true));
		      	valid = false;
		      }
		    	// System.out.println(et.validate());
		    } else if (v.type.equals("Course_Of_Action")) {
		    	CourseOfAction coa = new CourseOfAction().fromXMLString(xml);
		      if (!coa.validate()) {
		      	System.out.println(coa.toXMLString(true));
		      	valid = false;
		      }
		    	// System.out.println(coa.validate());
		    } else {
		    	System.out.println("COULD NOT FIND -------------- > " + v.type);
		    	valid = false;
		    }
		    if (!valid) {
		    	return false;
		    }
		  }
		} catch (SAXException e) {
		  e.printStackTrace();
		}

		return valid;
	}

	@Test 
	public void testVulnerabilityExploit() throws Exception {
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testVulnerabilityExploit()");

		String stix1 =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:metasploit-2e579a0a-0c44-4311-b6f0-a8fee86c3949\""+
			"    timestamp=\"2015-12-07T23:26:28.613Z\""+
			"    xmlns=\"http://xml/metadataSharing.xsd\""+
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
			"                    <stixCommon:Exploit_Target idref=\"Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760\" xmlns=\"\" xsi:type=\"et:ExploitTargetType\"/>"+
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix1);
		assertTrue(validate(stixElements));

		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);

		JSONObject vertices = graph.getJSONObject("vertices");

		assertTrue(true);

		System.out.println("Testing Exploit ...");
		//Element sourceElement = stixElements.get("stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d");
		assertTrue(vertices.has("stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d"));
		JSONObject vertex = vertices.getJSONObject("stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d");
		assertEquals(vertex.getString("vertexType"), "Exploit");
		assertEquals(vertex.getString("name"), "stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d");
		assertEquals(vertex.get("source").toString(), "[Metasploit]");
		assertEquals(vertex.get("description").toString(), "[This module exploits a buffer overflow vulnerability.]");
	  //	assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		assertEquals(vertex.get("shortDescription").toString(), "[AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow]");
		
		System.out.println("Testing Vulnerability Vertex ... ");
		String id = "Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760"));
		vertex = vertices.getJSONObject("Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797760");
		assertEquals(vertex.getString("vertexType"), "Vulnerability");
		assertEquals(vertex.getString("name"), "CVE-2009-3699");
		assertEquals(vertex.get("source").toString(), "[Metasploit]");
		assertEquals(vertex.get("description").toString(), "[CVE-2009-3699]");
	  //	assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Exploit -> Exploits -> Vulnerability Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("CVE-2009-3699") && 
				outVertName.equals("stucco:exploit-503fe717-e832-48c6-afd0-a93b65ce373d") && 
				relation.equals("Exploits")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
	}

	@Test 
	public void testMalwareIP() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testMalwareIP()");
		
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));

		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);

		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Malware Vertex ... ");
		String id = "stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3";
		//Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3"));
		JSONObject vertex = vertices.getJSONObject("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3");
		assertEquals(vertex.getString("vertexType"), "Malware");
		assertEquals(vertex.getString("name"), "stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3");
		assertEquals(vertex.get("source").toString(), "[1d4.us]");
		assertEquals(vertex.get("description").toString(), "[Scanner]");
		
		System.out.println("Testing IP Vertex ... ");
		id = "Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229"));
		vertex = vertices.getJSONObject("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229");
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
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("103.36.125.189") && 
				outVertName.equals("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3") && 
				relation.equals("UsesIP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testMalwareDuplicateIP() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testMalwareDuplicateIP()");
		
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
			"        <cybox:Observable id=\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea63000\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>HTTPRequest</cyboxCommon:Information_Source_Type>"+
			"            </cybox:Observable_Source>"+
			"            <cybox:Object id=\"stucco:ip-1730444733\">"+
			"                <cybox:Description>Description</cybox:Description>"+
			"                <cybox:Properties category=\"ipv4-addr\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));

		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);

		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Malware Vertex ... ");
		String id = "stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3";
		//Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3"));
		JSONObject vertex = vertices.getJSONObject("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3");
		assertEquals(vertex.getString("vertexType"), "Malware");
		assertEquals(vertex.getString("name"), "stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3");
		assertEquals(vertex.get("source").toString(), "[1d4.us]");
		assertEquals(vertex.get("description").toString(), "[Scanner]");
		
		System.out.println("Testing IP Vertex ... ");
		id = "Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229") || vertices.has("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea63000"));
		vertex = vertices.optJSONObject("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229");
		if (vertex == null) {
			vertex = vertices.optJSONObject("Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea63000");
		}
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "103.36.125.189");
		assertEquals(vertex.getLong("ipInt"), ipToLong("103.36.125.189"));
		assertTrue(vertex.get("source").toString().contains("1d4.us"));
		assertTrue(vertex.get("description").toString().contains("103.36.125.189"));
		
		JSONArray edges = graph.getJSONArray("edges");
		
		System.out.println("Testing Malware -> Uses_IP -> IP Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("103.36.125.189") && 
				outVertName.equals("stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3") && 
				relation.equals("UsesIP")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testFlowAddressIpPort() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testFlowAddressIpPort()");
		
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));

		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);

		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Flow Vertex ... ");
		String id = "stucco:flow-da6b7a73-6ed4-4d9a-b8dd-b770e2619ffb";
		//Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:flow-da6b7a73-6ed4-4d9a-b8dd-b770e2619ffb"));
		JSONObject vertex = vertices.getJSONObject("stucco:flow-da6b7a73-6ed4-4d9a-b8dd-b770e2619ffb");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Network Flow");
		assertEquals(vertex.getString("name"), "10.10.10.1:56867_through_10.10.10.100:22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1, port 56867 to 10.10.10.100, port 22]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	
		
		System.out.println("Testing (Source) Address Vertex ... ");
		id = "stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f";	
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f"));
		vertex = vertices.getJSONObject("stucco:address-f6e40756-f29f-462c-aa9d-3c90af97626f");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Socket Address");
		assertEquals(vertex.getString("name"), "10.10.10.1:56867");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1, port 56867]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) Address Vertex ... ");
		id = "stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd"));
		vertex = vertices.getJSONObject("stucco:address-046baefe-f1d0-45ee-91c3-a9a22a7e6ddd");
		assertEquals(vertex.getString("observableType"), "Socket Address");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("name"), "10.10.10.100:22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.100, port 22]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Source) IP Vertex ... ");
		id = "stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489"));
		vertex = vertices.getJSONObject("stucco:ip-8134dbc0-ffa4-44cd-89d2-1d7428c08489");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("observableType"), "Address");
		assertEquals(vertex.getString("name"), "10.10.10.1");
		assertEquals(vertex.getLong("ipInt"), ipToLong("10.10.10.1"));
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.1]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) IP Vertex ... ");
		id = "stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a"));
		vertex = vertices.getJSONObject("stucco:ip-a5dff0b3-0f2f-4308-a16d-949c5826cf1a");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("observableType"), "Address");
		assertEquals(vertex.getString("name"), "10.10.10.100");
		assertEquals(vertex.getLong("ipInt"), ipToLong("10.10.10.100"));
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[10.10.10.100]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Source) Port Vertex ... ");
		id = "stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09"));
		vertex = vertices.getJSONObject("stucco:port-6e8e3e78-962a-408e-9495-be65b11fff09");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Port");
		assertEquals(vertex.getString("name"), "56867");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[56867]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing (Destination) Port Vertex ... ");
		id = "stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26"));
		vertex = vertices.getJSONObject("stucco:port-2ce88ec7-6ace-4d70-aa31-ad6aa8129f26");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Port");
		assertEquals(vertex.getString("name"), "22");
		assertEquals(vertex.get("source").toString(), "[Argus]");
		assertEquals(vertex.get("description").toString(), "[22]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Flow -> Src_Socket_Address -> Address Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("10.10.10.1:56867") && 
				outVertName.equals("10.10.10.1:56867_through_10.10.10.100:22") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing Flow -> Dest_Socket_Address -> Address Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("10.10.10.100:22") && 
				outVertName.equals("10.10.10.1:56867_through_10.10.10.100:22") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Source) Address -> Has_IP -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("10.10.10.1") && 
				outVertName.equals("10.10.10.1:56867") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Destination) Address -> Has_IP -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("10.10.10.100") && 
				outVertName.equals("10.10.10.100:22") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Source) Address -> Has_Port -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("56867") && 
				outVertName.equals("10.10.10.1:56867") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing (Destination) Address -> Has_Port -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("22") && 
				outVertName.equals("10.10.10.100:22") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

	}	

	@Test 
	public void testOrganizationAddressRangeAS() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testOrganizationAddressRangeAS()");
		
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
			"                <cybox:Properties category=\"ipv4-addr\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    <AddressObj:Address_Value apply_condition=\"ANY\" condition=\"InclusiveBetween\" delimiter=\" - \">69.19.190.0 - 69.19.190.255</AddressObj:Address_Value>"+
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
			"                    <cybox:Related_Object idref=\"stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95\" />"+
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
			"                <cybox:Properties xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WhoisObj:WhoisObjectType\">"+
			"                    <WhoisObj:Registrants>"+
			"                        <WhoisObj:Registrant>"+
			"                            <WhoisObj:Address>US</WhoisObj:Address>"+
			"                            <WhoisObj:Organization>O1.com</WhoisObj:Organization>"+
			"                            <WhoisObj:Registrant_ID>01CO-ARIN</WhoisObj:Registrant_ID>"+
			"                        </WhoisObj:Registrant>"+
			"                    </WhoisObj:Registrants>"+
			"                </cybox:Properties>"+
			"                <cybox:Related_Objects>"+
			"                    <cybox:Related_Object idref=\"stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f\" />"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);

		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Organization Vertex ... ");
		String id = "stucco:organization-548c49e0-4a24-443d-80f6-ec6885bab598";
		//Element sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:organization-548c49e0-4a24-443d-80f6-ec6885bab598"));
		JSONObject vertex = vertices.getJSONObject("stucco:organization-548c49e0-4a24-443d-80f6-ec6885bab598");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Whois");
		assertEquals(vertex.getString("name"), "O1.com");
		assertEquals(vertex.get("source").toString(), "[CAIDA]");
		String description = vertex.get("description").toString();
		assertTrue(description.contains("Organization O1.com located in US has a range of IP addresses"));
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	
		
		System.out.println("Testing AS Vertex ... ");
		id = "stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f";
		//sourceElement = stixElements.get(id);
		assertTrue(vertices.has("stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f"));
		vertex = vertices.getJSONObject("stucco:as-16650bdd-96a4-46f4-9fec-032ac7092f5f");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "AS");
		assertEquals(vertex.getString("name"), "19864");
		//	assertEquals(vertex.getString("number"), "19864");
		assertEquals(vertex.get("source").toString(), "[CAIDA]");
		description = vertex.get("description").toString();
		assertTrue(description.contains("AS O1COMM has ASN 19864"));
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing AddressRange Vertex ... ");
		id = "stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95";

		assertTrue(vertices.has("stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95"));
		vertex = vertices.getJSONObject("stucco:addressRange-5d7163b7-6a6d-4538-ad0f-fc0de204aa95");
		assertEquals(vertex.getString("vertexType"), "AddressRange");
		assertEquals(vertex.getString("observableType"), "Address");
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
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("19864") && 
				outVertName.equals("O1.com") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
		System.out.println("Testing AS -> Contains -> AddressRange Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("69.19.190.0 - 69.19.190.255") && 
				outVertName.equals("19864") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
		
	}

	@Test 
	public void testSoftware() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testSoftware()");
		
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Software Vertex ... ");
		String id = "stucco:software-69a621f6-d22c-4d9c-a758-bc465dd8235b";
		// Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:software-69a621f6-d22c-4d9c-a758-bc465dd8235b");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Product");
		assertEquals(vertex.getString("name"), "cpe::1024cms:1024_cms:0.7:::");
		assertEquals(vertex.get("source").toString(), "[CPE]");
		assertEquals(vertex.get("description").toString(), "[1024cms.org 1024 CMS 0.7]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
	}

	@Test 
	public void testDNSRecordIpDNSName() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testDNSRecordIpDNSName()");
		
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
			"                    <cybox:Related_Object idref=\"stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44\" />" +
			"                    <cybox:Related_Object idref=\"stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63\" />" +
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing DNSRecord ... ");
		String id = "stucco:dnsRecord-559dd80d-97b6-4c08-97eb-37001d2c59cb";
		//Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:dnsRecord-559dd80d-97b6-4c08-97eb-37001d2c59cb");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "DNS Record");
		assertEquals(vertex.getString("name"), "DALE-PC.ORNL.GOV_resolved_to_89.79.77.77");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertTrue(vertex.get("description").toString().contains("Requested domain name DALE-PC.ORNL.GOV resolved to IP address 89.79.77.77"));
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing IP ... ");
		id = "stucco:ip-bd47ec2e-14a8-4126-8ae0-092b8276bf09";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-bd47ec2e-14a8-4126-8ae0-092b8276bf09");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "89.79.77.77");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[89.79.77.77]");
		assertEquals(vertex.get("ipInt").toString(), "1498369357");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing IP ... ");
		id = "stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-fe34621f-26a0-48f1-b5e3-3fa641011d63");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "128.219.177.244");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[128.219.177.244]");
		assertEquals(vertex.get("ipInt").toString(), "2161881588");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		System.out.println("Testing IP ... ");
		id = "stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-3183aead-8eb9-401e-8b30-63f917218e44");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("name"), "68.87.73.245");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[68.87.73.245]");
		assertEquals(vertex.get("ipInt").toString(), "1146571253");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		System.out.println("Testing DNSName ... ");
		id = "stucco:dnsName-d64a70b3-6371-4fce-a0bf-24d902a3dc6c";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:dnsName-d64a70b3-6371-4fce-a0bf-24d902a3dc6c");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Domain Name");
		assertEquals(vertex.getString("name"), "DALE-PC.ORNL.GOV");
		assertEquals(vertex.get("source").toString(), "[DNSRecord]");
		assertEquals(vertex.get("description").toString(), "[DALE-PC.ORNL.GOV]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing DNSRecord -> Requested_DNSName -> DNSName Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("DALE-PC.ORNL.GOV") && 
				outVertName.equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Requested_IP -> Requested IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("89.79.77.77") && 
				outVertName.equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Served_By -> Server IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("128.219.177.244") && 
				outVertName.equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing DNSRecord -> Requested_By -> Requested by IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("68.87.73.245") && 
				outVertName.equals("DALE-PC.ORNL.GOV_resolved_to_89.79.77.77") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testServicePort() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testServicePort()");
		
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Service ... ");
		String id = "stucco:service-f7791dd0-03d7-48f2-a323-c02c97008c4b";
		//Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:service-f7791dd0-03d7-48f2-a323-c02c97008c4b");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Process");
		assertEquals(vertex.getString("name"), "ssh");
		assertEquals(vertex.get("source").toString(), "[service_list]");
		assertEquals(vertex.get("description").toString(), "[The Secure Shell (SSH) Protocol]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing Port ... ");
		id = "stucco:port-cbd16bd3-38d6-49e5-86aa-39784a774c14";
		// sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:port-cbd16bd3-38d6-49e5-86aa-39784a774c14");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Port");
		assertEquals(vertex.getString("name"), "22");
		assertEquals(vertex.get("source").toString(), "[service_list]");
		assertEquals(vertex.get("description").toString(), "[22]");
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Service -> Runs_On -> Port Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("22") && 
				outVertName.equals("ssh") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHTTPRequestIpPortDNSName() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testHTTPRequestIpPortDNSName()");
		
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
			"                    <cybox:Related_Object idref=\"stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c\" />"+
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing HTTPRequest ... ");
		String id = "stucco:httpRequest-59629f94-c963-4788-b897-b1e02bf92cab";
		//Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:httpRequest-59629f94-c963-4788-b897-b1e02bf92cab");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "HTTP Session");
		assertEquals(vertex.getString("name"), "/tv2n/vpaid/8bc5b7b");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[HTTP request of URL /tv2n/vpaid/8bc5b7b]");

		System.out.println("Testing IP ... ");
		id = "stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-cddd9469-b8a6-4d8b-97d9-830fc191490c");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("observableType"), "Address");
		assertEquals(vertex.getString("name"), "54.192.138.232");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[54.192.138.232]");
		assertEquals(vertex.get("ipInt").toString(), "918588136");

		System.out.println("Testing IP ... ");
		id = "stucco:ip-86590b2c-5e14-4880-85ee-bc9d5c9a3302";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-86590b2c-5e14-4880-85ee-bc9d5c9a3302");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("observableType"), "Address");
		assertEquals(vertex.getString("name"), "128.219.49.13");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[128.219.49.13]");
		assertEquals(vertex.get("ipInt").toString(), "2161848589");

		System.out.println("Testing DNSName ... ");
		id = "stucco:dnsName-9e1fbf26-d46a-43cd-825a-145b31935344";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:dnsName-9e1fbf26-d46a-43cd-825a-145b31935344");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Domain Name");
		assertEquals(vertex.getString("name"), "cdn455.telemetryverification.net");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertTrue(vertex.get("description").toString().contains("cdn455.telemetryverification.net"));

		System.out.println("Testing Port ... ");
		id = "stucco:port-290e65ae-45df-431b-b051-6121201e9a6e";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:port-290e65ae-45df-431b-b051-6121201e9a6e");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Port");
		assertEquals(vertex.getString("name"), "80");
		assertEquals(vertex.get("source").toString(), "[HTTPRequest]");
		assertEquals(vertex.get("description").toString(), "[80]");

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing HTTPRequest -> IP Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("128.219.49.13") && 
				outVertName.equals("/tv2n/vpaid/8bc5b7b") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing HTTPRequest -> Served_On -> Port Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("80") && 
				outVertName.equals("/tv2n/vpaid/8bc5b7b") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing HTTPRequest -> Served_By -> DNSName Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("cdn455.telemetryverification.net") && 
				outVertName.equals("/tv2n/vpaid/8bc5b7b") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHostSoftware() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testHostSoftware()");
		
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
			"										 <cyboxCommon:Custom_Properties> " +
			"											 <cyboxCommon:Property name=\"Part\">/a</cyboxCommon:Property> " +
			"										 </cyboxCommon:Custom_Properties> " +
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
			"                    <cybox:Related_Object idref=\"stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02\" />"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");
		
		System.out.println("Testing Software ... ");
		String id = "stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02";
		//Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:software-f159ef23-0b06-452c-81fa-0a266c1d1e02");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Product");
		assertEquals(vertex.getString("name"), "cpe:::ftp:0.17-25:::");
		assertEquals(vertex.get("source").toString(), "[PackageList]");
		assertEquals(vertex.get("description").toString(), "[ftp version 0.17-25]");
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-e11a469e-a66a-42b5-835f-d6599cc592a6";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:hostname-e11a469e-a66a-42b5-835f-d6599cc592a6");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Hostname");
		assertEquals(vertex.getString("name"), "stucco1");
		assertEquals(vertex.get("source").toString(), "[PackageList]");
		assertTrue(vertex.get("description").toString().contains("stucco1"));

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Host -> Runs -> Software Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("cpe:::ftp:0.17-25:::") && 
				outVertName.equals("stucco1") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testHostSoftwareAccountIp() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testHostSoftwareAccountIp()");
		
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
			"                    <cyboxCommon:Custom_Properties>"+
			"                        <cyboxCommon:Property name=\"Part\">/a</cyboxCommon:Property>"+
			"                    </cyboxCommon:Custom_Properties>"+
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
			"                    <AccountObj:Domain>domain.com</AccountObj:Domain>"+
			"                    <UserAccountObj:Full_Name>Full_Name</UserAccountObj:Full_Name>"+
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Account ... ");
		String id = "stucco:account-c42d3219-bb0a-486e-b144-e3c8887a504e";
		//Element sourceElement = stixElements.get(id);
		JSONObject vertex = vertices.getJSONObject("stucco:account-c42d3219-bb0a-486e-b144-e3c8887a504e");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "User Account");
		assertEquals(vertex.getString("name"), "StuccoUser");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertTrue(vertex.get("description").toString().contains("StuccoUser"));
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-01b000b8-9326-43d5-b94a-60f299c9dd35";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:hostname-01b000b8-9326-43d5-b94a-60f299c9dd35");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Hostname");
		assertEquals(vertex.getString("name"), "host_at_192.168.10.11");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertTrue(vertex.get("description").toString().contains("host at 192.168.10.11"));
		
		System.out.println("Testing Host ... ");
		id = "stucco:hostname-67ae4885-0914-429c-ac61-fa8f1932ec53";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:hostname-67ae4885-0914-429c-ac61-fa8f1932ec53");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Hostname");
		assertEquals(vertex.getString("name"), "StuccoHost");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertTrue(vertex.get("description").toString().contains("StuccoHost"));
		
		System.out.println("Testing Software ... ");
		id = "stucco:software-cc2b74cc-7cf2-4383-be29-a41f67332aca";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:software-cc2b74cc-7cf2-4383-be29-a41f67332aca");
		assertEquals(vertex.getString("vertexType"), "Observable");
		assertEquals(vertex.getString("observableType"), "Product");
		assertEquals(vertex.getString("name"), "cpe:::sshd::::");
		assertEquals(vertex.get("source").toString(), "[LoginEvent]");
		assertTrue(vertex.get("description").toString().contains("sshd"));

		System.out.println("Testing IP ... ");
		id = "stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241";
		//sourceElement = stixElements.get(id);
		vertex = vertices.getJSONObject("stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241");
		assertEquals(vertex.getString("vertexType"), "IP");
		assertEquals(vertex.getString("observableType"), "Address");
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
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("host_at_192.168.10.11") && 
				outVertName.equals("StuccoUser") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Account -> Logs_In_To -> Host Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("StuccoHost") && 
				outVertName.equals("StuccoUser") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Host -> Runs -> Software Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("cpe:::sshd::::") && 
				outVertName.equals("StuccoHost") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);

		System.out.println("Testing Host -> Resolved_To -> IP Edge ...");
		edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("192.168.10.11") && 
				outVertName.equals("host_at_192.168.10.11") && 
				relation.equals("Sub-Observable")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testVulnerabilityWithSolution() throws Exception {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testVulnerabilityWithSolution()");
		
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
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		System.out.println("Testing Vulnerability Vertex ... ");
		JSONObject vertex = vertices.getJSONObject("stucco:vulnerability-b73ca23e-66d6-4fd7-89b4-30859796b38e");
		assertEquals(vertex.getString("vertexType"), "Vulnerability");
		assertEquals(vertex.getString("name"), "CVE-2015-2098");
		assertEquals(vertex.get("source").toString(), "[Bugtraq]");
		assertEquals(vertex.get("description").toString(), "[WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.]");
		assertEquals(vertex.get("shortDescription").toString(), "[WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities]");
		//assertEquals(vertex.get("publishedDate"), "2015-03-27T00:00:00.000-04:00");
		String id = "stucco:vulnerability-b73ca23e-66d6-4fd7-89b4-30859796b38e";
		//Element sourceElement = stixElements.get(id);
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));
		
		System.out.println("Testing Course_Of_Action Vertex ... ");
		vertex = vertices.getJSONObject("stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b");
		assertEquals(vertex.getString("vertexType"), "Course_Of_Action");
		assertEquals(vertex.getString("name"), "stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b");
		assertTrue(vertex.get("description").toString().contains("Solution: Currently, we are not aware of any vendor-supplied patches. If you feel we are in error or are aware of more recent information, please mail us at: vuldb@securityfocus.com."));
		id = "stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b";
		//sourceElement = stixElements.get(id);
		// assertEquals(vertex.getString("sourceDocument"), new XMLOutputter().outputString(sourceElement));

		JSONArray edges = graph.getJSONArray("edges");

		System.out.println("Testing Vulnerability -> PotentialCOA -> Course_Of_Action Edge ...");
		boolean edgeExists = false;
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String inVertName = vertices.getJSONObject(inVertID).getString("name");
			String outVertID = edge.getString("outVertID");
			String outVertName = vertices.getJSONObject(outVertID).getString("name");
			String relation = edge.getString("relation");
			if (inVertName.equals("stucco:vulnerability-9e478710-0aa7-4fdc-b768-44c4d0f8812b") && 
				outVertName.equals("CVE-2015-2098") && 
				relation.equals("PotentialCOA")) {
				edgeExists = true;
				break;
			}
		}
		assertTrue(edgeExists);
	}

	@Test 
	public void testIncident() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testIncident()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
			"<stix:STIX_Package " +
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
			"    xmlns:incident=\"http://stix.mitre.org/Incident-1\" " +
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
			"    xmlns:ta=\"http://stix.mitre.org/ThreatActor-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\" > " +
			"        <cybox:Observable " +
			"            id=\"stucco:Observable-d4a1b891-2905-49b9-90af-1c614528cdb2\" xmlns:stucco=\"gov.ornl.stucco\"> " +
			"            <cybox:Object> " +
			"                <cybox:Properties " +
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\"> " +
			"                    <PortObj:Port_Value>80</PortObj:Port_Value> " +
			"                </cybox:Properties> " +
			"            </cybox:Object> " +
			"        </cybox:Observable> " +
			"    </stix:Observables> " +
			"    <stix:TTPs> " +
			"        <stix:TTP id=\"stucco:TTP-40d40e02-7055-43d3-8e7e-f566e4f53a3b\" " +
			"            xmlns:stucco=\"gov.ornl.stucco\" " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
			"            <ttp:Title>TTP Title</ttp:Title> " +
			"            <ttp:Behavior> " +
			"                <ttp:Exploits> " +
			"                    <ttp:Exploit> " +
			"                        <ttp:Title>Exploit Title 1</ttp:Title> " +
			"                        <ttp:Description>Exploit Description 1</ttp:Description> " +
			"                    </ttp:Exploit> " +
			"                </ttp:Exploits> " +
			"            </ttp:Behavior> " +
			"        </stix:TTP> " +
			"    </stix:TTPs> " +
			"    <stix:Incidents> " +
			"        <stix:Incident " +
			"            id=\"stucco:Incident-19ef98a1-c297-4756-a99d-43b885ef0129\" " +
			"            xmlns:stucco=\"gov.ornl.stucco\" " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"incident:IncidentType\"> " +
			"            <incident:Title>Incident Title</incident:Title> " +
			"            <incident:External_ID>External ID</incident:External_ID> " +
			"            <incident:Description>Incident description 1</incident:Description> " +
			"            <incident:Description>Incident description 2</incident:Description> " +
			"            <incident:Related_Observables> " +
			"                <incident:Related_Observable> " +
			"                    <stixCommon:Observable idref=\"stucco:Observable-d4a1b891-2905-49b9-90af-1c614528cdb2\"/> " +
			"                </incident:Related_Observable> " +
			"            </incident:Related_Observables> " +
			"            <incident:Leveraged_TTPs> " +
			"                <incident:Leveraged_TTP> " +
			"                    <stixCommon:TTP " +
			"                        idref=\"stucco:TTP-40d40e02-7055-43d3-8e7e-f566e4f53a3b\" xsi:type=\"ttp:TTPType\"/> " +
			"                </incident:Leveraged_TTP> " +
			"            </incident:Leveraged_TTPs> " +
			"            <incident:Attributed_Threat_Actors> " +
			"                <incident:Threat_Actor> " +
			"                    <stixCommon:Threat_Actor " +
			"                        idref=\"stucco:ThreatActors-3aaad08a-ea7a-44e1-b809-7d3d6b5f3678\" xsi:type=\"ta:ThreatActorType\"/> " +
			"                </incident:Threat_Actor> " +
			"            </incident:Attributed_Threat_Actors> " +
			"            <incident:Information_Source> " +
			"                <stixCommon:Identity> " +
			"                    <stixCommon:Name>Source Name 1</stixCommon:Name> " +
			"                </stixCommon:Identity> " +
			"                <stixCommon:Contributing_Sources> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 2</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 3</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                </stixCommon:Contributing_Sources> " +
			"            </incident:Information_Source> " +
			"        </stix:Incident> " +
			"    </stix:Incidents> " +
			"    <stix:Threat_Actors> " +
			"        <stix:Threat_Actor " +
			"            id=\"stucco:ThreatActors-3aaad08a-ea7a-44e1-b809-7d3d6b5f3678\" " +
			"            xmlns:stucco=\"gov.ornl.stucco\" " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ta:ThreatActorType\"> " +
			"            <ta:Title>ThreatActor Title</ta:Title> " +
			"            <ta:Description>ThreatActor Description 1</ta:Description> " +
			"            <ta:Description>ThreatActor Description 2</ta:Description> " +
			"            <ta:Identity> " +
			"                <stixCommon:Name>ThreatActor Name</stixCommon:Name> " +
			"                <stixCommon:Related_Identities> " +
			"                    <stixCommon:Related_Identity> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>ThreatActor Related Name</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Related_Identity> " +
			"                </stixCommon:Related_Identities> " +
			"            </ta:Identity> " +
			"        </stix:Threat_Actor> " +
			"    </stix:Threat_Actors> " +
			"</stix:STIX_Package> ";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		JSONObject vertex = vertices.getJSONObject("stucco:Incident-19ef98a1-c297-4756-a99d-43b885ef0129");
		
		System.out.println("Testing Incident Vertex ... ");
		assertEquals(vertex.getString("vertexType"), "Incident");
		assertEquals(vertex.getString("name"), "stucco:Incident-19ef98a1-c297-4756-a99d-43b885ef0129");
		Set<String> descriptionSet = (HashSet<String>) vertex.get("description");
		assertTrue(descriptionSet.contains("Incident description 1"));
		assertTrue(descriptionSet.contains("Incident description 2"));
		Set<String> sourceSet = (HashSet<String>) vertex.get("source");
		assertTrue(sourceSet.contains("Source Name 1"));
		assertTrue(sourceSet.contains("Source Name 2"));
		assertTrue(sourceSet.contains("Source Name 3"));
		String sourceDocument = vertex.getString("sourceDocument");
		/*
		Incident incident = new Incident().fromXMLString(sourceDocument);
		try {
			assertTrue(incident.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
		*/
	}

	@Test 
	public void testCourseOfAction() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testCourseOfAction()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " +
			"    xmlns:APIObj=\"http://cybox.mitre.org/objects#APIObject-2\" " +
			"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
			"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\"> " +
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
			"        <cybox:Observable " +
			"            id=\"stucco:Observable-c715ad25-2c4e-4b46-90a7-3f266bb831c5\" xmlns:stucco=\"gov.ornl.stucco\"> " +
			"            <cybox:Object> " +
			"                <cybox:Properties " +
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"APIObj:APIObjectType\"> " +
			"                    <APIObj:Function_Name>Function_Name</APIObj:Function_Name> " +
			"                </cybox:Properties> " +
			"            </cybox:Object> " +
			"        </cybox:Observable> " +
			"    </stix:Observables> " +
			"    <stix:Exploit_Targets> " +
			"        <stixCommon:Exploit_Target " +
			"            id=\"stucco:ExploitTarget-3e96b726-92cc-4d22-b110-59a9264b10ca\" " +
			"            xmlns:stucco=\"gov.ornl.stucco\" " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
			"            <et:Vulnerability> " +
			"                <et:Title>Title 1</et:Title> " +
			"                <et:Description>Description 1</et:Description> " +
			"                <et:CVE_ID>CVE-2009-2897</et:CVE_ID> " +
			"            </et:Vulnerability> " +
			"            <et:Potential_COAs> " +
			"                <et:Potential_COA> " +
			"                    <stixCommon:Course_Of_Action " +
			"                        idref=\"stucco:COA-41bc383d-c596-4aa0-96dc-d741d8e5c513\" xsi:type=\"coa:CourseOfActionType\"/> " +
			"                </et:Potential_COA> " +
			"            </et:Potential_COAs> " +
			"        </stixCommon:Exploit_Target> " +
			"    </stix:Exploit_Targets> " +
			"    <stix:Courses_Of_Action> " +
			"        <stix:Course_Of_Action " +
			"            id=\"stucco:COA-41bc383d-c596-4aa0-96dc-d741d8e5c513\" " +
			"            xmlns:stucco=\"gov.ornl.stucco\" " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"coa:CourseOfActionType\"> " +
			"            <coa:Title>Course Of Action</coa:Title> " +
			"            <coa:Parameter_Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
			"                <cybox:Observable idref=\"stucco:Observable-c715ad25-2c4e-4b46-90a7-3f266bb831c5\"/> " +
			"            </coa:Parameter_Observables> " +
			"        </stix:Course_Of_Action> " +
			"    </stix:Courses_Of_Action> " +
			"</stix:STIX_Package> ";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		JSONObject vertex = vertices.getJSONObject("stucco:COA-41bc383d-c596-4aa0-96dc-d741d8e5c513");
		
		System.out.println("Testing Course_Of_Action Vertex ... ");
		assertEquals(vertex.getString("vertexType"), "Course_Of_Action");
		assertEquals(vertex.getString("name"), "stucco:COA-41bc383d-c596-4aa0-96dc-d741d8e5c513");
		String sourceDocument = vertex.getString("sourceDocument");
		CourseOfAction coa = new CourseOfAction().fromXMLString(sourceDocument);
		try {
			assertTrue(coa.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testIndicator() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testIndicator()");
		
		String stix = 
			"   <stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " +
			"       xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
			"       xmlns:campaign=\"http://stix.mitre.org/Campaign-1\" " +
			"       xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
			"       xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
			"       xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
			"       xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
			"       xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
			"       <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
			"           <cybox:Observable " +
			"               id=\"stucco:Observable-49d26fef-3e9c-4667-8668-f3fe1fc166c7\" xmlns:stucco=\"gov.ornl.stucco\"> " +
			"               <cybox:Object> " +
			"                   <cybox:Properties " +
			"                       xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\"> " +
			"                       <PortObj:Port_Value>80</PortObj:Port_Value> " +
			"                   </cybox:Properties> " +
			"                </cybox:Object> " +
			"            </cybox:Observable> " +
			"        </stix:Observables> " +
			"        <stix:Indicators> " +
			"            <stix:Indicator " +
			"                id=\"stucco:Indicator-276366cb-fd43-48d4-b809-e5d5bb91a78d\" " +
			"                xmlns:stucco=\"gov.ornl.stucco\" " +
			"                xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
			"                <indicator:Title>Indicator Title</indicator:Title> " +
			"                <indicator:Alternative_ID>Some Alternative ID 1</indicator:Alternative_ID> " +
			"                <indicator:Alternative_ID>Some Alternative ID 2</indicator:Alternative_ID> " +
			"                <indicator:Description>Indicator Description 1</indicator:Description> " +
			"                <indicator:Description>Indicator Description 2</indicator:Description> " +
			"                <indicator:Observable idref=\"stucco:Observable-49d26fef-3e9c-4667-8668-f3fe1fc166c7\"/> " +
			"                <indicator:Indicated_TTP> " +
			"                    <stixCommon:TTP " +
			"                        idref=\"stucco:TTP-23bc34d0-2c90-4570-a267-e1dd70274829\" xsi:type=\"ttp:TTPType\"/> " +
			"               </indicator:Indicated_TTP> " +
			"               <indicator:Suggested_COAs> " +
			"                   <indicator:Suggested_COA> " +
			"                       <stixCommon:Course_Of_Action " +
			"                           idref=\"stucco:COA-dfc100f2-ca09-4a8c-b885-9fa09a9bc646\" xsi:type=\"coa:CourseOfActionType\"/> " +
			"                   </indicator:Suggested_COA> " +
			"               </indicator:Suggested_COAs> " +
			/*
			"             <indicator:Related_Campaigns> " +
			"                   <indicator:Related_Campaign> " +
			"                       <stixCommon:Campaign> " +
			"                           <stixCommon:Names> " +
			"                               <stixCommon:Name>Campaign Name</stixCommon:Name> " +
			"                           </stixCommon:Names> " +
			"                       </stixCommon:Campaign> " +
			"                   </indicator:Related_Campaign> " +
			"               </indicator:Related_Campaigns> " +
			*/
			"               <indicator:Producer> " +
			"                   <stixCommon:Identity> " +
			"                       <stixCommon:Name>Source Name 1</stixCommon:Name> " +
			"                   </stixCommon:Identity> " +
			"                   <stixCommon:Contributing_Sources> " +
			"                       <stixCommon:Source> " +
			"                           <stixCommon:Identity> " +
			"                               <stixCommon:Name>Source Name 2</stixCommon:Name> " +
			"                           </stixCommon:Identity> " +
			"                       </stixCommon:Source> " +
			"                       <stixCommon:Source> " +
			"                           <stixCommon:Identity> " +
			"                               <stixCommon:Name>Source Name 3</stixCommon:Name> " +
			"                           </stixCommon:Identity> " +
			"                       </stixCommon:Source> " +
			"                    </stixCommon:Contributing_Sources> " +
			"                </indicator:Producer> " +
			"            </stix:Indicator> " +
			"        </stix:Indicators> " +
			"        <stix:TTPs> " +
			"            <stix:TTP id=\"stucco:TTP-23bc34d0-2c90-4570-a267-e1dd70274829\" " +
			"                xmlns:stucco=\"gov.ornl.stucco\" " +
			"                xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
			"                <ttp:Behavior> " +
			"                    <ttp:Malware> " +
			"                        <ttp:Malware_Instance> " +
			"                            <ttp:Name>Malware Name</ttp:Name> " +
			"                        </ttp:Malware_Instance> " +
			"                    </ttp:Malware> " +
			"                </ttp:Behavior> " +
			"            </stix:TTP> " +
			"        </stix:TTPs> " +
			"        <stix:Courses_Of_Action> " +
			"            <stix:Course_Of_Action " +
			"                id=\"stucco:COA-dfc100f2-ca09-4a8c-b885-9fa09a9bc646\" " +
			"                xmlns:stucco=\"gov.ornl.stucco\" " +
			"                xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"coa:CourseOfActionType\"> " +
			"                <coa:Title>Course Of Action</coa:Title> " +
			"            </stix:Course_Of_Action> " +
			"        </stix:Courses_Of_Action> " +
			"        <stix:Campaigns> " +
			"            <stix:Campaign " +
			"                id=\"stucco:Campaign-35ee44f2-daa3-4cf7-8a9b-de166d994e5d\" " +
			"                xmlns:stucco=\"gov.ornl.stucco\" " +
			"                xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"campaign:CampaignType\"> " +
			"                <campaign:Names> " +
			"                    <campaign:Name>Another Campaign Name</campaign:Name> " +
			"                </campaign:Names> " +
			"            </stix:Campaign> " +
			"        </stix:Campaigns> " +
			"    </stix:STIX_Package>";
		
		/*
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		System.out.println(pack.toXMLString(true));

		try {
			System.out.println(pack.validate());
			assertTrue(pack.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
		*/

		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		JSONObject vertex = vertices.getJSONObject("stucco:Indicator-276366cb-fd43-48d4-b809-e5d5bb91a78d");
		System.out.println("Testing Indicator Vertex ... ");
		assertEquals(vertex.getString("vertexType"), "Indicator");
		assertEquals(vertex.getString("name"), "stucco:Indicator-276366cb-fd43-48d4-b809-e5d5bb91a78d");
		Set<String> descriptionSet = (HashSet<String>) vertex.get("description");
		assertTrue(descriptionSet.contains("Indicator Description 1"));
		assertTrue(descriptionSet.contains("Indicator Description 2"));
		Set<String> sourceSet = (HashSet<String>) vertex.get("source");
		assertTrue(sourceSet.contains("Source Name 1"));
		assertTrue(sourceSet.contains("Source Name 2"));
		assertTrue(sourceSet.contains("Source Name 3"));
		String sourceDocument = vertex.getString("sourceDocument");
		Indicator indicator = new Indicator().fromXMLString(sourceDocument);
		try {
			assertTrue(indicator.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testThreatActor() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testThreatActor()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
			"<stix:STIX_Package xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:ta=\"http://stix.mitre.org/ThreatActor-1\"> " +
			"    <stix:Threat_Actors> " +
			"        <stix:Threat_Actor " +
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ta:ThreatActorType\"> " +
			"            <ta:Title>ThreatActor Title</ta:Title> " +
			"            <ta:Description>ThreatActor Description 1</ta:Description> " +
			"            <ta:Description>ThreatActor Description 2</ta:Description> " +
			"            <ta:Identity> " +
			"                <stixCommon:Name>ThreatActor Name</stixCommon:Name> " +
			"                <stixCommon:Related_Identities> " +
			"                    <stixCommon:Related_Identity> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>ThreatActor Related Name</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Related_Identity> " +
			"                </stixCommon:Related_Identities> " +
			"            </ta:Identity> " +
			"            <ta:Information_Source> " +
			"                <stixCommon:Identity> " +
			"                    <stixCommon:Name>Source Name 1</stixCommon:Name> " +
			"                </stixCommon:Identity> " +
			"                <stixCommon:Contributing_Sources> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 2</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 3</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                </stixCommon:Contributing_Sources> " +
			"            </ta:Information_Source> " +
			"        </stix:Threat_Actor> " +
			"    </stix:Threat_Actors> " +
			"</stix:STIX_Package> ";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		JSONObject vertex = null;
		for (Object key : vertices.keySet()) {
			vertex = vertices.getJSONObject(key.toString());
			break;
		}
		
		System.out.println("Testing ThreatActor Vertex ... ");
		assertEquals(vertex.getString("vertexType"), "Threat_Actor");
		assertEquals(vertex.getString("name"), "ThreatActor Name");
		Set<String> descriptionSet = (HashSet<String>) vertex.get("description");
		assertTrue(descriptionSet.contains("ThreatActor Description 1"));
		assertTrue(descriptionSet.contains("ThreatActor Description 2"));
		Set<String> sourceSet = (HashSet<String>) vertex.get("source");
		assertTrue(sourceSet.contains("Source Name 1"));
		assertTrue(sourceSet.contains("Source Name 2"));
		assertTrue(sourceSet.contains("Source Name 3"));
		String sourceDocument = vertex.getString("sourceDocument");
		ThreatActor ta = new ThreatActor().fromXMLString(sourceDocument);
		try {
			assertTrue(ta.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
	}

	//@Test 
	public void testTTP() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testTTP()");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
			"<stix:STIX_Package xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
			"    <stix:TTPs> " +
			"        <stix:TTP xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\" > " +
			"            <ttp:Title>TTP Title</ttp:Title> " +
			"            <ttp:Description>TTP Description 1</ttp:Description> " +
			"            <ttp:Description>TTP Description 2</ttp:Description> " +
			"            <ttp:Information_Source> " +
			"                <stixCommon:Identity> " +
			"                    <stixCommon:Name>Source Name 1</stixCommon:Name> " +
			"                </stixCommon:Identity> " +
			"                <stixCommon:Contributing_Sources> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 2</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                    <stixCommon:Source> " +
			"                        <stixCommon:Identity> " +
			"                            <stixCommon:Name>Source Name 3</stixCommon:Name> " +
			"                        </stixCommon:Identity> " +
			"                    </stixCommon:Source> " +
			"                </stixCommon:Contributing_Sources> " +
			"            </ttp:Information_Source> " +
			"        </stix:TTP> " +
			"    </stix:TTPs> " +
			"</stix:STIX_Package> ";
		
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		assertTrue(validate(stixElements));
		
		GraphConstructor graphConstructor = new GraphConstructor();
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");

		JSONObject vertex = null;
		for (Object key : vertices.keySet()) {
			vertex = vertices.getJSONObject(key.toString());
			break;
		}
		
		System.out.println("Testing TTP Vertex ... ");
		assertEquals(vertex.getString("vertexType"), "TTP");
		Set<String> descriptionSet = (HashSet<String>) vertex.get("description");
		assertTrue(descriptionSet.contains("TTP Description 1"));
		assertTrue(descriptionSet.contains("TTP Description 2"));
		Set<String> sourceSet = (HashSet<String>) vertex.get("source");
		assertTrue(sourceSet.contains("Source Name 1"));
		assertTrue(sourceSet.contains("Source Name 2"));
		assertTrue(sourceSet.contains("Source Name 3"));
		String sourceDocument = vertex.getString("sourceDocument");
		TTP ttp = new TTP().fromXMLString(sourceDocument);
		try {
			assertTrue(ttp.validate());
		} catch (SAXException e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testAllStixElements() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testAllStixElements()");
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
				"			<et:Description>Description</et:Description> " +
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
			Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
			assertTrue(validate(stixElements));
			
			GraphConstructor graphConstructor = new GraphConstructor();
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			JSONObject vertices = graph.getJSONObject("vertices");

			System.out.println("Testing Indicator Vertex ... ");
			JSONObject vertex = vertices.getJSONObject("stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca");
			assertEquals(vertex.getString("vertexType"), "Indicator");
			assertEquals(vertex.getString("name"), "stucco:indicator-f6c15754-2fe0-4b1e-a43a-8fc1df4e49ca");
			Set<String> descriptionSet = (HashSet<String>) vertex.get("description");
			assertTrue(descriptionSet.contains("Indicator description"));
			Set<String> sourceSet = (HashSet<String>) vertex.get("source");
			assertTrue(sourceSet.contains("Source One"));
			assertTrue(sourceSet.contains("Source Two"));
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
			assertEquals(vertex.get("description").toString(), "[Course_Of_Action description]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			CourseOfAction coa = new CourseOfAction().fromXMLString(sourceDocument);
			assertTrue(coa.validate());
			
			System.out.println("Testing Exploit_Target Vertex ... ");
			vertex = vertices.getJSONObject("stucco:et-52962ed3-1c7f-4cac-bedb-d49bb429b625");
			assertEquals(vertex.getString("vertexType"), "Weakness");
			assertEquals(vertex.getString("name"), "CWE-93487297");
			assertEquals(vertex.get("description").toString(), "[Description of this weakness]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			ExploitTarget et = new ExploitTarget().fromXMLString(sourceDocument);
			assertTrue(et.validate());
			
			System.out.println("Testing Campaign Vertex ... ");
			vertex = vertices.getJSONObject("stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c");
			assertEquals(vertex.getString("vertexType"), "Campaign");
			assertEquals(vertex.getString("name"), "stucco:campaign-a2dec921-6a3f-49e4-b415-402b376fff5c");
			assertEquals(vertex.get("description").toString(), "[Campaign description]");
			assertTrue(vertex.has("sourceDocument"));
			sourceDocument = vertex.getString("sourceDocument");
			Campaign campaign = new Campaign().fromXMLString(sourceDocument);
			assertTrue(campaign.validate());
			
			System.out.println("Testing Threat_Actor Vertex ... ");
			vertex = vertices.getJSONObject("stucco:threat-9f055e12-d799-47d8-84a5-f018ee1ccb99");
			assertEquals(vertex.getString("vertexType"), "Threat_Actor");
			assertEquals(vertex.getString("name"), "Actor's name");
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

	@Test 
	public void testCyboxElements() {
		
		System.out.println("[RUNNING] gov.ornl.stucco.GraphConstructorTest.testAllCyboxElements()");
	
		PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
		GraphConstructor graphConstructor = new GraphConstructor();

		System.out.println("Testing API ... ");
		
		String stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:APIObj=\"http://cybox.mitre.org/objects#APIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-ff9f3206-b2a4-4535-b5f2-95864be01cc2\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"APIObj:APIObjectType\"> " + 
			"                    <APIObj:Function_Name>Function_Name</APIObj:Function_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";

		Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(stix);
		JSONObject graph = graphConstructor.constructGraph(stixElements);
		JSONObject vertices = graph.getJSONObject("vertices");	
		JSONObject vertex = vertices.getJSONObject("stucco:Observable-ff9f3206-b2a4-4535-b5f2-95864be01cc2");
		String name = vertex.getString("name");
		//	assertEquals(name, "Function_Name");
		String observableType = vertex.getString("observableType");
		assertEquals(observableType, "API");

		System.out.println("Testing Account ... ");
		stix = 	
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AccountObj=\"http://cybox.mitre.org/objects#AccountObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-8867dee9-eb87-4510-a3e1-3b3bcd0392d8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AccountObj:AccountObjectType\"> " + 
			"                    <AccountObj:Domain>Domain</AccountObj:Domain> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";

		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-8867dee9-eb87-4510-a3e1-3b3bcd0392d8");
		name = vertex.getString("name");
		assertEquals(name, "Domain");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Account");
	
		System.out.println("Testing Windows Computer Account ... ");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinComputerAccountObj=\"http://cybox.mitre.org/objects#WinComputerAccountObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-dd9dc105-caa4-40e6-aca9-91c452f397e1\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinComputerAccountObj:WindowsComputerAccountObjectType\"> " + 
			"                    <WinComputerAccountObj:Fully_Qualified_Name> " + 
			"                        <WinComputerAccountObj:NetBEUI_Name>BEUI_Name</WinComputerAccountObj:NetBEUI_Name> " + 
			"                        <WinComputerAccountObj:Full_Name>Full_Name</WinComputerAccountObj:Full_Name> " + 
			"                    </WinComputerAccountObj:Fully_Qualified_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";

		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-dd9dc105-caa4-40e6-aca9-91c452f397e1");
		name = vertex.getString("name");
		assertEquals(name, "Full_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Computer Account");

		System.out.println("Testing ARP Cache ... ");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ARPCacheObj=\"http://cybox.mitre.org/objects#ARPCacheObject-1\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-75ea0896-3986-4a8a-96ae-0f150b4ee499\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ARPCacheObj:ARPCacheObjectType\"> " + 
			"                    <ARPCacheObj:ARP_Cache_Entry> " + 
			"                        <ARPCacheObj:IP_Address> " + 
			"                            <AddressObj:Address_Value>222.333.444.111</AddressObj:Address_Value> " + 
			"                        </ARPCacheObj:IP_Address> " + 
			"                    </ARPCacheObj:ARP_Cache_Entry> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);

		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-75ea0896-3986-4a8a-96ae-0f150b4ee499");
		name = vertex.getString("name");
		assertEquals(name, "222.333.444.111");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "ARP Cache");
	
		System.out.println("Testing Artifact ... ");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ArtifactObj=\"http://cybox.mitre.org/objects#ArtifactObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-3c37be62-3f00-4eca-b857-84703fb529f4\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ArtifactObj:ArtifactObjectType\"> " + 
			"                    <ArtifactObj:Raw_Artifact>Artifact_Value</ArtifactObj:Raw_Artifact> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";

		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-3c37be62-3f00-4eca-b857-84703fb529f4");
		name = vertex.getString("name");
		assertEquals(name, "Artifact_Value");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Artifact");
		
		System.out.println("Testing Code ... ");
		stix =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:CodeObj=\"http://cybox.mitre.org/objects#CodeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-23fa76ef-c5b5-4888-84d2-1fced870452e\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CodeObj:CodeObjectType\"> " + 
			"                    <CodeObj:Code_Language>Code_Language</CodeObj:Code_Language> " + 
			"                    <CodeObj:Code_Segment>Code_Segment</CodeObj:Code_Segment> " + 
			"                    <CodeObj:Code_Segment_XOR>Code_Segment_Xor</CodeObj:Code_Segment_XOR> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-23fa76ef-c5b5-4888-84d2-1fced870452e");
		name = vertex.getString("name");
		assertEquals(name, "Code_Segment");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Code");
		
		System.out.println("Testing Device ... ");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:DeviceObj=\"http://cybox.mitre.org/objects#DeviceObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-3e157d73-6086-4382-901a-12227905b7d1\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DeviceObj:DeviceObjectType\"> " + 
			"                    <DeviceObj:Model>Model</DeviceObj:Model> " + 
			"                    <DeviceObj:Serial_Number>Serial_Number</DeviceObj:Serial_Number> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-3e157d73-6086-4382-901a-12227905b7d1");
		name = vertex.getString("name");
		assertEquals(name, "Model");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Device");
		
		System.out.println("Testing Disk ... ");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:DiskObj=\"http://cybox.mitre.org/objects#DiskObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-ea9dee68-d6b7-42a2-b56b-a5f1abd85e97\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DiskObj:DiskObjectType\"> " + 
			"                    <DiskObj:Disk_Name>Disk_Name</DiskObj:Disk_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-ea9dee68-d6b7-42a2-b56b-a5f1abd85e97");
		name = vertex.getString("name");
		assertEquals(name, "Disk_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Disk");

		System.out.println("Testing Disk Partition ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:DiskPartitionObj=\"http://cybox.mitre.org/objects#DiskPartitionObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-f8e60b33-c3b1-4b12-85ec-7a6f303c03e8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DiskPartitionObj:DiskPartitionObjectType\"> " + 
			"                    <DiskPartitionObj:Partition_ID>Partition_ID</DiskPartitionObj:Partition_ID> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-f8e60b33-c3b1-4b12-85ec-7a6f303c03e8");
		name = vertex.getString("name");
		assertEquals(name, "Partition_ID");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Disk Partition");

		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:DNSCacheObj=\"http://cybox.mitre.org/objects#DNSCacheObject-2\" " + 
			"    xmlns:DNSRecordObj=\"http://cybox.mitre.org/objects#DNSRecordObject-2\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-bdba9c62-48bc-4677-b98e-2447ad54d253\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DNSCacheObj:DNSCacheObjectType\"> " + 
			"                    <DNSCacheObj:DNS_Cache_Entry> " + 
			"                        <DNSCacheObj:DNS_Entry> " + 
			"                            <DNSRecordObj:Description>NS_Record_Description</DNSRecordObj:Description> " + 
			"                            <DNSRecordObj:Domain_Name> " + 
			"                                <URIObj:Value>Domain_Name</URIObj:Value> " + 
			"                            </DNSRecordObj:Domain_Name> " + 
			"                            <DNSRecordObj:IP_Address> " + 
			"                                <AddressObj:Address_Value>IP_Address</AddressObj:Address_Value> " + 
			"                            </DNSRecordObj:IP_Address> " + 
			"                        </DNSCacheObj:DNS_Entry> " + 
			"                    </DNSCacheObj:DNS_Cache_Entry> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";

		System.out.println("Testing DNS Query ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:DNSQueryObj=\"http://cybox.mitre.org/objects#DNSQueryObject-2\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-e03c67b4-fa57-4b47-8add-e86500e63536\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"DNSQueryObj:DNSQueryObjectType\"> " + 
			"                    <DNSQueryObj:Transaction_ID>ID</DNSQueryObj:Transaction_ID> " + 
			"                    <DNSQueryObj:Question> " + 
			"                        <DNSQueryObj:QName> " + 
			"                            <URIObj:Value>Domain_Name</URIObj:Value> " + 
			"                        </DNSQueryObj:QName> " + 
			"                    </DNSQueryObj:Question> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-e03c67b4-fa57-4b47-8add-e86500e63536");
		name = vertex.getString("name");
		assertEquals(name, "Domain_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "DNS Query");
		
		
		System.out.println("Testing File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-1e2c5459-e089-4d7f-82a0-b421b829517e\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"FileObj:FileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-1e2c5459-e089-4d7f-82a0-b421b829517e");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "File");

		System.out.println("Testing GUI ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:GUIObj=\"http://cybox.mitre.org/objects#GUIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c8ebbf7d-eec4-4425-a027-e872f05fdb3a\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"GUIObj:GUIObjectType\"> " + 
			"                    <GUIObj:Height>Int_Height</GUIObj:Height> " + 
			"                    <GUIObj:Width>Int_Width</GUIObj:Width> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c8ebbf7d-eec4-4425-a027-e872f05fdb3a");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "GUI");
		
		System.out.println("Testing GUI Dialog Box ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:GUIDialogBoxObj=\"http://cybox.mitre.org/objects#GUIDialogboxObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c6a6dd40-42c3-4854-abde-a334340a6152\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"GUIDialogBoxObj:GUIDialogboxObjectType\"> " + 
			"                    <GUIDialogBoxObj:Box_Caption>Box_Caption</GUIDialogBoxObj:Box_Caption> " + 
			"                    <GUIDialogBoxObj:Box_Text>Box_Text</GUIDialogBoxObj:Box_Text> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c6a6dd40-42c3-4854-abde-a334340a6152");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "GUI Dialogbox");

		System.out.println("Testing GUI Window ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:GUIWindowObj=\"http://cybox.mitre.org/objects#GUIWindowObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-b4f4b483-1c0a-4648-b31c-2954167f0b61\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"GUIWindowObj:GUIWindowObjectType\"> " + 
			"                    <GUIWindowObj:Window_Display_Name>Window_Display_Name</GUIWindowObj:Window_Display_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-b4f4b483-1c0a-4648-b31c-2954167f0b61");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "GUI Window");

		System.out.println("Testing HTTP Session ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:HTTPSessionObj=\"http://cybox.mitre.org/objects#HTTPSessionObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-0c798bbb-a0f6-42b4-9fb4-e194952b9156\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"HTTPSessionObj:HTTPSessionObjectType\"> " + 
			"                    <HTTPSessionObj:HTTP_Request_Response> " + 
			"                        <HTTPSessionObj:HTTP_Client_Request> " + 
			"                            <HTTPSessionObj:HTTP_Request_Line> " + 
			"                                <HTTPSessionObj:Value>Http_Request_Line</HTTPSessionObj:Value> " + 
			"                            </HTTPSessionObj:HTTP_Request_Line> " + 
			"                        </HTTPSessionObj:HTTP_Client_Request> " + 
			"                        <HTTPSessionObj:HTTP_Server_Response> " + 
			"                            <HTTPSessionObj:HTTP_Status_Line> " + 
			"                                <HTTPSessionObj:Version>Reponse_Version</HTTPSessionObj:Version> " + 
			"                                <HTTPSessionObj:Status_Code>200_Status_Code</HTTPSessionObj:Status_Code> " + 
			"                                <HTTPSessionObj:Reason_Phrase>Reason_Phrase</HTTPSessionObj:Reason_Phrase> " + 
			"                            </HTTPSessionObj:HTTP_Status_Line> " + 
			"                            <HTTPSessionObj:HTTP_Response_Header> " + 
			"                                <HTTPSessionObj:Raw_Header>Raw_Header</HTTPSessionObj:Raw_Header> " + 
			"                            </HTTPSessionObj:HTTP_Response_Header> " + 
			"                            <HTTPSessionObj:HTTP_Message_Body> " + 
			"                                <HTTPSessionObj:Message_Body>Message_body</HTTPSessionObj:Message_Body> " + 
			"                            </HTTPSessionObj:HTTP_Message_Body> " + 
			"                        </HTTPSessionObj:HTTP_Server_Response> " + 
			"                    </HTTPSessionObj:HTTP_Request_Response> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-0c798bbb-a0f6-42b4-9fb4-e194952b9156");
		name = vertex.getString("name");
		assertEquals(name, "Http_Request_Line");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "HTTP Session");

		System.out.println("Testing Archive File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ArchiveFileObj=\"http://cybox.mitre.org/objects#ArchiveFileObject-1\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-80c04278-a870-4848-b97d-a543ae98c0ac\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ArchiveFileObj:ArchiveFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-80c04278-a870-4848-b97d-a543ae98c0ac");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Archive File");

		System.out.println("Testing Windows File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:WinFileObj=\"http://cybox.mitre.org/objects#WinFileObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-86d64eee-c2ca-4db5-b14a-9286fc07b56e\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinFileObj:WindowsFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-86d64eee-c2ca-4db5-b14a-9286fc07b56e");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows File");

		System.out.println("Testing Windows Executable File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:WinExecutableFileObj=\"http://cybox.mitre.org/objects#WinExecutableFileObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-d4deb3df-eee5-4ce7-a527-a79446d2a1d6\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinExecutableFileObj:WindowsExecutableFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-d4deb3df-eee5-4ce7-a527-a79446d2a1d6");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Executable File");

		System.out.println("Testing PDF File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:PDFFileObj=\"http://cybox.mitre.org/objects#PDFFileObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-aecd6054-4420-4421-8a6f-13aa07f2f057\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PDFFileObj:PDFFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-aecd6054-4420-4421-8a6f-13aa07f2f057");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "PDF File");

		System.out.println("Testing Image File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:ImageFileObj=\"http://cybox.mitre.org/objects#ImageFileObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-b39dc251-9db1-4490-8320-9c118f064463\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ImageFileObj:ImageFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-b39dc251-9db1-4490-8320-9c118f064463");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Image File");


		System.out.println("Testing Unix File ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " + 
			"    xmlns:UnixFileObj=\"http://cybox.mitre.org/objects#UnixFileObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-ae48bb93-48c2-4f9e-9358-2df33470a75a\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixFileObj:UnixFileObjectType\"> " + 
			"                    <FileObj:File_Name>File_Name</FileObj:File_Name> " + 
			"                    <FileObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </FileObj:Hashes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-ae48bb93-48c2-4f9e-9358-2df33470a75a");
		name = vertex.getString("name");
		assertEquals(name, "File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix File");

		System.out.println("Testing Library ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:LibraryObj=\"http://cybox.mitre.org/objects#LibraryObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-a08e1fd5-c4e3-42f0-b8dc-3ef90c1a3e85\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"LibraryObj:LibraryObjectType\"> " + 
			"                    <LibraryObj:Name>Library_Name</LibraryObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-a08e1fd5-c4e3-42f0-b8dc-3ef90c1a3e85");
		name = vertex.getString("name");
		assertEquals(name, "Library_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Library");

		System.out.println("Testing Linux Package ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:LinuxPackageObj=\"http://cybox.mitre.org/objects#LinuxPackageObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-83e465a9-9a49-455c-b8e7-8e62f5e0ef0d\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"LinuxPackageObj:LinuxPackageObjectType\"> " + 
			"                    <LinuxPackageObj:Name>Linux_Package</LinuxPackageObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-83e465a9-9a49-455c-b8e7-8e62f5e0ef0d");
		name = vertex.getString("name");
		assertEquals(name, "Linux_Package");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Linux Package");


		System.out.println("Testing Memory ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:MemoryObj=\"http://cybox.mitre.org/objects#MemoryObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-3ae3dc55-9407-432b-8867-5d5833b4174c\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"MemoryObj:MemoryObjectType\"> " + 
			"                    <MemoryObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </MemoryObj:Hashes> " + 
			"                    <MemoryObj:Name>Memory_Name</MemoryObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-3ae3dc55-9407-432b-8867-5d5833b4174c");
		name = vertex.getString("name");
		assertEquals(name, "Memory_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Memory");

		System.out.println("Testing Windows Memory Page Region ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:MemoryObj=\"http://cybox.mitre.org/objects#MemoryObject-2\" " + 
			"    xmlns:WinMemoryPageRegionObj=\"http://cybox.mitre.org/objects#WinMemoryPageRegionObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c2344585-a2b2-4988-8b11-521905c1e8b0\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinMemoryPageRegionObj:WindowsMemoryPageRegionObjectType\"> " + 
			"                    <MemoryObj:Hashes> " + 
			"                        <cyboxCommon:Hash> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                            <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value</cyboxCommon:Simple_Hash_Value> " + 
			"                            <cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                                <cyboxCommon:Block_Hash> " + 
			"                                    <cyboxCommon:Block_Hash_Value> " + 
			"                                    <cyboxCommon:Fuzzy_Hash_Value>Fuzzy_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Fuzzy_Hash_Value> " + 
			"                                    <cyboxCommon:Simple_Hash_Value>Simple_Hash_Value of Fuzzy_Hash_Structure</cyboxCommon:Simple_Hash_Value> " + 
			"                                    </cyboxCommon:Block_Hash_Value> " + 
			"                                </cyboxCommon:Block_Hash> " + 
			"                            </cyboxCommon:Fuzzy_Hash_Structure> " + 
			"                        </cyboxCommon:Hash> " + 
			"                    </MemoryObj:Hashes> " + 
			"                    <MemoryObj:Name>Memory_Name</MemoryObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c2344585-a2b2-4988-8b11-521905c1e8b0");
		name = vertex.getString("name");
		assertEquals(name, "Memory_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Memory Page Region");


		System.out.println("Testing Mutex ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:MutexObj=\"http://cybox.mitre.org/objects#MutexObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c9d4279c-944f-4a7e-87e4-c9091256410a\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"MutexObj:MutexObjectType\"> " + 
			"                    <MutexObj:Name>Mutex_Name</MutexObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c9d4279c-944f-4a7e-87e4-c9091256410a");
		name = vertex.getString("name");
		assertEquals(name, "Mutex_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Mutex");



		System.out.println("Testing Network Connection ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:HostnameObj=\"http://cybox.mitre.org/objects#HostnameObject-1\" " + 
			"    xmlns:NetworkConnectionObj=\"http://cybox.mitre.org/objects#NetworkConnectionObject-2\" " + 
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " + 
			"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-78ea4ebf-ca22-434e-a0f9-2e92fbf3c948\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkConnectionObj:NetworkConnectionObjectType\"> " + 
			"                    <NetworkConnectionObj:Source_Socket_Address> " + 
			"                        <SocketAddressObj:Hostname> " + 
			"                            <HostnameObj:Hostname_Value>Source_Hostname</HostnameObj:Hostname_Value> " + 
			"                        </SocketAddressObj:Hostname> " + 
			"                        <SocketAddressObj:IP_Address> " + 
			"                            <AddressObj:Address_Value>Source_IP_Address</AddressObj:Address_Value> " + 
			"                        </SocketAddressObj:IP_Address> " + 
			"                        <SocketAddressObj:Port> " + 
			"                            <PortObj:Port_Value>Source_Port_Value</PortObj:Port_Value> " + 
			"                        </SocketAddressObj:Port> " + 
			"                    </NetworkConnectionObj:Source_Socket_Address> " + 
			"                    <NetworkConnectionObj:Destination_Socket_Address> " + 
			"                        <SocketAddressObj:Hostname> " + 
			"                            <HostnameObj:Hostname_Value>Destination_Hostname</HostnameObj:Hostname_Value> " + 
			"                        </SocketAddressObj:Hostname> " + 
			"                        <SocketAddressObj:IP_Address> " + 
			"                            <AddressObj:Address_Value>Destination_IP_Address</AddressObj:Address_Value> " + 
			"                        </SocketAddressObj:IP_Address> " + 
			"                        <SocketAddressObj:Port> " + 
			"                            <PortObj:Port_Value>Destination_Port_Value</PortObj:Port_Value> " + 
			"                        </SocketAddressObj:Port> " + 
			"                    </NetworkConnectionObj:Destination_Socket_Address> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-78ea4ebf-ca22-434e-a0f9-2e92fbf3c948");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-78ea4ebf-ca22-434e-a0f9-2e92fbf3c948");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Connection");

		System.out.println("Testing Network Packet ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:PacketObj=\"http://cybox.mitre.org/objects#PacketObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-fb36d966-742a-430c-a8b0-6d9da0d20cc6\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PacketObj:NetworkPacketObjectType\"> " + 
			"                    <PacketObj:Transport_Layer> " + 
			"                        <PacketObj:TCP> " + 
			"                            <PacketObj:Data> " + 
			"                                <cyboxCommon:Data_Segment>Data_Segment_Value</cyboxCommon:Data_Segment> " + 
			"                            </PacketObj:Data> " + 
			"                        </PacketObj:TCP> " + 
			"                    </PacketObj:Transport_Layer> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-fb36d966-742a-430c-a8b0-6d9da0d20cc6");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-fb36d966-742a-430c-a8b0-6d9da0d20cc6");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Packet");


		System.out.println("Testing Network Route Entry ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:NetworkRouteEntryObj=\"http://cybox.mitre.org/objects#NetworkRouteEntryObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-d4be6c04-a3d6-4e39-a7e1-2b7ea0be9027\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkRouteEntryObj:NetworkRouteEntryObjectType\"> " + 
			"                    <NetworkRouteEntryObj:Destination_Address> " + 
			"                        <AddressObj:Address_Value>Destination_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Destination_Address> " + 
			"                    <NetworkRouteEntryObj:Origin> " + 
			"                        <AddressObj:Address_Value>Origin_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Origin> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-d4be6c04-a3d6-4e39-a7e1-2b7ea0be9027");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-d4be6c04-a3d6-4e39-a7e1-2b7ea0be9027");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Route Entry");

		System.out.println("Testing Unix Network Route ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:NetworkRouteEntryObj=\"http://cybox.mitre.org/objects#NetworkRouteEntryObject-2\" " + 
			"    xmlns:UnixNetworkRouteEntryObj=\"http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-d1fe8ea3-d5b4-428e-9032-bdfdb2af471f\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixNetworkRouteEntryObj:UnixNetworkRouteEntryObjectType\"> " + 
			"                    <NetworkRouteEntryObj:Destination_Address> " + 
			"                        <AddressObj:Address_Value>Destination_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Destination_Address> " + 
			"                    <NetworkRouteEntryObj:Origin> " + 
			"                        <AddressObj:Address_Value>Origin_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Origin> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-d1fe8ea3-d5b4-428e-9032-bdfdb2af471f");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-d1fe8ea3-d5b4-428e-9032-bdfdb2af471f");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix Network Route Entry");

		System.out.println("Testing Windows Network Route Entry ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:NetworkRouteEntryObj=\"http://cybox.mitre.org/objects#NetworkRouteEntryObject-2\" " + 
			"    xmlns:WinNetworkRouteEntryObj=\"http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-3a5e9b3d-f540-433e-9483-5846ad077794\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinNetworkRouteEntryObj:WindowsNetworkRouteEntryObjectType\"> " + 
			"                    <NetworkRouteEntryObj:Destination_Address> " + 
			"                        <AddressObj:Address_Value>Destination_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Destination_Address> " + 
			"                    <NetworkRouteEntryObj:Origin> " + 
			"                        <AddressObj:Address_Value>Origin_Address</AddressObj:Address_Value> " + 
			"                    </NetworkRouteEntryObj:Origin> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-3a5e9b3d-f540-433e-9483-5846ad077794");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-3a5e9b3d-f540-433e-9483-5846ad077794");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Network Route Entry");
		
		System.out.println("Testing Network Route ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:NetworkRouteEntryObj=\"http://cybox.mitre.org/objects#NetworkRouteEntryObject-2\" " + 
			"    xmlns:NetworkRouteObj=\"http://cybox.mitre.org/objects#NetworkRouteObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-740399b4-fe65-4857-8d2e-32711801b31b\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkRouteObj:NetRouteObjectType\"> " + 
			"                    <NetworkRouteObj:Network_Route_Entries> " + 
			"                        <NetworkRouteObj:Network_Route_Entry> " + 
			"                            <NetworkRouteEntryObj:Destination_Address> " + 
			"                                <AddressObj:Address_Value>Destination_Address</AddressObj:Address_Value> " + 
			"                            </NetworkRouteEntryObj:Destination_Address> " + 
			"                            <NetworkRouteEntryObj:Origin> " + 
			"                                <AddressObj:Address_Value>Origin_Address</AddressObj:Address_Value> " + 
			"                            </NetworkRouteEntryObj:Origin> " + 
			"                        </NetworkRouteObj:Network_Route_Entry> " + 
			"                    </NetworkRouteObj:Network_Route_Entries> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-740399b4-fe65-4857-8d2e-32711801b31b");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-740399b4-fe65-4857-8d2e-32711801b31b");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Route");

		System.out.println("Testing Network Socket ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:HostnameObj=\"http://cybox.mitre.org/objects#HostnameObject-1\" " + 
			"    xmlns:NetworkSocketObj=\"http://cybox.mitre.org/objects#NetworkSocketObject-2\" " + 
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " + 
			"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-85d23a49-4d07-456f-91e6-abc00c44197c\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkSocketObj:NetworkSocketObjectType\"> " + 
			"                    <NetworkSocketObj:Local_Address> " + 
			"                        <SocketAddressObj:Hostname> " + 
			"                            <HostnameObj:Hostname_Value>Local_Hostname</HostnameObj:Hostname_Value> " + 
			"                        </SocketAddressObj:Hostname> " + 
			"                        <SocketAddressObj:IP_Address> " + 
			"                            <AddressObj:Address_Value>Local_IP_Address</AddressObj:Address_Value> " + 
			"                        </SocketAddressObj:IP_Address> " + 
			"                        <SocketAddressObj:Port> " + 
			"                            <PortObj:Port_Value>Local_Port</PortObj:Port_Value> " + 
			"                        </SocketAddressObj:Port> " + 
			"                    </NetworkSocketObj:Local_Address> " + 
			"                    <NetworkSocketObj:Remote_Address> " + 
			"                        <SocketAddressObj:Hostname> " + 
			"                            <HostnameObj:Hostname_Value>Remote_Hostname</HostnameObj:Hostname_Value> " + 
			"                        </SocketAddressObj:Hostname> " + 
			"                        <SocketAddressObj:IP_Address> " + 
			"                            <AddressObj:Address_Value>Remote_IP_Address</AddressObj:Address_Value> " + 
			"                        </SocketAddressObj:IP_Address> " + 
			"                        <SocketAddressObj:Port> " + 
			"                            <PortObj:Port_Value>Remote_Port</PortObj:Port_Value> " + 
			"                        </SocketAddressObj:Port> " + 
			"                    </NetworkSocketObj:Remote_Address> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-85d23a49-4d07-456f-91e6-abc00c44197c");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-85d23a49-4d07-456f-91e6-abc00c44197c");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Socket");


		System.out.println("Testing Network Subnet ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:NetworkRouteEntryObj=\"http://cybox.mitre.org/objects#NetworkRouteEntryObject-2\" " + 
			"    xmlns:NetworkSubnetObj=\"http://cybox.mitre.org/objects#NetworkSubnetObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-9c8aab5f-c320-40a4-90c6-0b9b019bae36\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"NetworkSubnetObj:NetworkSubnetObjectType\"> " + 
			"                    <NetworkSubnetObj:Name>Subnet_Name</NetworkSubnetObj:Name> " + 
			"                    <NetworkSubnetObj:Routes> " + 
			"                        <NetworkSubnetObj:Route> " + 
			"                            <NetworkRouteEntryObj:Destination_Address> " + 
			"                                <AddressObj:Address_Value>Destination_Address</AddressObj:Address_Value> " + 
			"                            </NetworkRouteEntryObj:Destination_Address> " + 
			"                            <NetworkRouteEntryObj:Origin> " + 
			"                                <AddressObj:Address_Value>Origin_Address</AddressObj:Address_Value> " + 
			"                            </NetworkRouteEntryObj:Origin> " + 
			"                        </NetworkSubnetObj:Route> " + 
			"                    </NetworkSubnetObj:Routes> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-9c8aab5f-c320-40a4-90c6-0b9b019bae36");
		name = vertex.getString("name");
		assertEquals(name, "Subnet_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Network Subnet");

		System.out.println("Testing Pipe ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:PipeObj=\"http://cybox.mitre.org/objects#PipeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-4f5cc563-7f3c-466c-b71b-086c3b9e78ff\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PipeObj:PipeObjectType\"> " + 
			"                    <PipeObj:Name>Pipe_Name</PipeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-4f5cc563-7f3c-466c-b71b-086c3b9e78ff");
		name = vertex.getString("name");
		assertEquals(name, "Pipe_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Pipe");

		System.out.println("Testing Unix Pipe ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:PipeObj=\"http://cybox.mitre.org/objects#PipeObject-2\" " + 
			"    xmlns:UnixPipeObj=\"http://cybox.mitre.org/objects#UnixPipeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-0969755f-32b1-41ea-9b1a-a0f2451aebbd\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixPipeObj:UnixPipeObjectType\"> " + 
			"                    <PipeObj:Name>Pipe_Name</PipeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-0969755f-32b1-41ea-9b1a-a0f2451aebbd");
		name = vertex.getString("name");
		assertEquals(name, "Pipe_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix Pipe");

		System.out.println("Testing Windows Pipe ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:PipeObj=\"http://cybox.mitre.org/objects#PipeObject-2\" " + 
			"    xmlns:WinPipeObj=\"http://cybox.mitre.org/objects#WinPipeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-162a6a97-5fe8-4647-ade0-14883e0f3312\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinPipeObj:WindowsPipeObjectType\"> " + 
			"                    <PipeObj:Name>Pipe_Name</PipeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-162a6a97-5fe8-4647-ade0-14883e0f3312");
		name = vertex.getString("name");
		assertEquals(name, "Pipe_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Pipe");

		System.out.println("Testing Process ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-300f9ba7-4f78-4950-acb9-76436065810a\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProcessObj:ProcessObjectType\"> " + 
			"                    <ProcessObj:PID>PID</ProcessObj:PID> " + 
			"                    <ProcessObj:Name>Process_Name</ProcessObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-300f9ba7-4f78-4950-acb9-76436065810a");
		name = vertex.getString("name");
		assertEquals(name, "Process_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Process");

		System.out.println("Testing Unix Process ...");
		stix = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " + 
			"    xmlns:UnixProcessObj=\"http://cybox.mitre.org/objects#UnixProcessObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-1bb74c3d-2fe1-42b2-a9b8-ec255b3a8183\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixProcessObj:UnixProcessObjectType\"> " + 
			"                    <ProcessObj:PID>PID</ProcessObj:PID> " + 
			"                    <ProcessObj:Name>Process_Name</ProcessObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-1bb74c3d-2fe1-42b2-a9b8-ec255b3a8183");
		name = vertex.getString("name");
		assertEquals(name, "Process_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix Process");

		System.out.println("Testing Windows Process ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " + 
			"    xmlns:WinProcessObj=\"http://cybox.mitre.org/objects#WinProcessObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-dce0b6ab-7233-4517-9331-0df91cf0dd13\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinProcessObj:WindowsProcessObjectType\"> " + 
			"                    <ProcessObj:PID>PID</ProcessObj:PID> " + 
			"                    <ProcessObj:Name>Process_Name</ProcessObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-dce0b6ab-7233-4517-9331-0df91cf0dd13");
		name = vertex.getString("name");
		assertEquals(name, "Process_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Process");

		System.out.println("Testing Product ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-7f3666d5-869d-4366-95e9-9bf94425c099\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " + 
			"                    <ProductObj:Edition>edition</ProductObj:Edition> " + 
			"                    <ProductObj:Language>language</ProductObj:Language> " + 
			"                    <ProductObj:Product>product</ProductObj:Product> " + 
			"                    <ProductObj:Update>update</ProductObj:Update> " + 
			"                    <ProductObj:Vendor>vendor</ProductObj:Vendor> " + 
			"                    <ProductObj:Version>version</ProductObj:Version> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-7f3666d5-869d-4366-95e9-9bf94425c099");
		name = vertex.getString("name");
		assertEquals(name, "cpe::vendor:product:version:update:edition:language");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Product");



		System.out.println("Testing Windows Semaphore ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:SemaphoreObj=\"http://cybox.mitre.org/objects#SemaphoreObject-2\" " + 
			"    xmlns:WinSemaphoreObj=\"http://cybox.mitre.org/objects#WinSemaphoreObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-34c0f264-1652-419a-ba3a-015bcfdfdcf8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinSemaphoreObj:WindowsSemaphoreObjectType\"> " + 
			"                    <SemaphoreObj:Name>Semaphore_Name</SemaphoreObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
	  stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-34c0f264-1652-419a-ba3a-015bcfdfdcf8");
		name = vertex.getString("name");
		assertEquals(name, "Semaphore_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Semaphore");

		System.out.println("Testing Semaphore ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:SemaphoreObj=\"http://cybox.mitre.org/objects#SemaphoreObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-6ac2bf25-cf31-4933-b114-418be9885ee5\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SemaphoreObj:SemaphoreObjectType\"> " + 
			"                    <SemaphoreObj:Name>Semaphore_Name</SemaphoreObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-6ac2bf25-cf31-4933-b114-418be9885ee5");
		name = vertex.getString("name");
		assertEquals(name, "Semaphore_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Semaphore");

		System.out.println("Testing SMS Message ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:SMSMessageObj=\"http://cybox.mitre.org/objects#SMSMessageObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-60ffe0eb-72aa-4e96-8caf-89272443e84f\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SMSMessageObj:SMSMessageObjectType\"> " + 
			"                    <SMSMessageObj:Sender_Phone_Number>Sender_Phone_Number</SMSMessageObj:Sender_Phone_Number> " + 
			"                    <SMSMessageObj:Recipient_Phone_Number>Receipient_Phone_Number</SMSMessageObj:Recipient_Phone_Number> " + 
			"                    <SMSMessageObj:Sent_DateTime>Date_Time</SMSMessageObj:Sent_DateTime> " + 
			"                    <SMSMessageObj:Body>Message_Body</SMSMessageObj:Body> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-60ffe0eb-72aa-4e96-8caf-89272443e84f");
		name = vertex.getString("name");
		assertEquals(name, "Message_Body");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "SMS Message");

		System.out.println("Testing System ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:SystemObj=\"http://cybox.mitre.org/objects#SystemObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-cd9782ee-9cf4-4d35-83a0-f8b4c378b3fb\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SystemObj:SystemObjectType\"> " + 
			"                    <SystemObj:Hostname>Hostname</SystemObj:Hostname> " + 
			"                    <SystemObj:OS> " + 
			"                        <cyboxCommon:Identifier>Platform_Identifier_For_This_System</cyboxCommon:Identifier> " + 
			"                        <SystemObj:Build_Number>Build_Number</SystemObj:Build_Number> " + 
			"                    </SystemObj:OS> " + 
			"                    <SystemObj:Processor>Process</SystemObj:Processor> " + 
			"                    <SystemObj:Username>Username</SystemObj:Username> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-cd9782ee-9cf4-4d35-83a0-f8b4c378b3fb");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-cd9782ee-9cf4-4d35-83a0-f8b4c378b3fb");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "System");

		System.out.println("Testing Windows System ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:SystemObj=\"http://cybox.mitre.org/objects#SystemObject-2\" " + 
			"    xmlns:WinSystemObj=\"http://cybox.mitre.org/objects#WinSystemObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " + 
			"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-046f3b5d-6846-42ff-97ab-3a4b2b295afd\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinSystemObj:WindowsSystemObjectType\"> " + 
			"                    <SystemObj:Hostname>Hostname</SystemObj:Hostname> " + 
			"                    <SystemObj:OS> " + 
			"                        <cyboxCommon:Identifier>Platform_Identifier_For_This_System</cyboxCommon:Identifier> " + 
			"                        <SystemObj:Build_Number>Build_Number</SystemObj:Build_Number> " + 
			"                    </SystemObj:OS> " + 
			"                    <SystemObj:Processor>Process</SystemObj:Processor> " + 
			"                    <SystemObj:Username>Username</SystemObj:Username> " + 
			"                    <WinSystemObj:Product_ID>Product_Id</WinSystemObj:Product_ID> " + 
			"                    <WinSystemObj:Product_Name>Product_Name</WinSystemObj:Product_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-046f3b5d-6846-42ff-97ab-3a4b2b295afd");
		name = vertex.getString("name");
		assertEquals(name, "Product_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows System");

		System.out.println("Testing URI ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-73cadd8e-0d3b-4eb3-8c05-6cd96ab37951\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"URIObj:URIObjectType\"> " + 
			"                    <URIObj:Value>URI</URIObj:Value> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-73cadd8e-0d3b-4eb3-8c05-6cd96ab37951");
		name = vertex.getString("name");
		assertEquals(name, "URI");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "URI");


		System.out.println("Testing URL History ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:URLHistoryObj=\"http://cybox.mitre.org/objects#URLHistoryObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-66b5b0f0-3cff-448b-9bc5-5e82343adda0\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"URLHistoryObj:URLHistoryObjectType\"> " + 
			"                    <URLHistoryObj:URL_History_Entry> " + 
			"                        <URLHistoryObj:URL> " + 
			"                            <URIObj:Value>URL</URIObj:Value> " + 
			"                        </URLHistoryObj:URL> " + 
			"                        <URLHistoryObj:User_Profile_Name>User_Profile</URLHistoryObj:User_Profile_Name> " + 
			"                    </URLHistoryObj:URL_History_Entry> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-66b5b0f0-3cff-448b-9bc5-5e82343adda0");
		name = vertex.getString("name");
		assertEquals(name, "URL");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "URL History");


		System.out.println("Testing User Session ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:UserSessionObj=\"http://cybox.mitre.org/objects#UserSessionObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-bdeb5750-8348-45cf-b791-53a0cfec5a59\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UserSessionObj:UserSessionObjectType\"> " + 
			"                    <UserSessionObj:Effective_Group>Group</UserSessionObj:Effective_Group> " + 
			"                    <UserSessionObj:Effective_Group_ID>Group_ID</UserSessionObj:Effective_Group_ID> " + 
			"                    <UserSessionObj:Effective_User>User</UserSessionObj:Effective_User> " + 
			"                    <UserSessionObj:Effective_User_ID>User_ID</UserSessionObj:Effective_User_ID> " + 
			"                    <UserSessionObj:Login_Time>Login_Time</UserSessionObj:Login_Time> " + 
			"                    <UserSessionObj:Logout_Time>Logout_Time</UserSessionObj:Logout_Time> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-bdeb5750-8348-45cf-b791-53a0cfec5a59");
		name = vertex.getString("name");
		assertEquals(name, "Group");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "User Session");


		System.out.println("Testing Unix Volume ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:UnixVolumeObj=\"http://cybox.mitre.org/objects#UnixVolumeObject-2\" " + 
			"    xmlns:VolumeObj=\"http://cybox.mitre.org/objects#VolumeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-84494d3c-d338-45b6-8dbe-7f924ed332bb\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixVolumeObj:UnixVolumeObjectType\"> " + 
			"                    <VolumeObj:Name>Volume_Name</VolumeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-84494d3c-d338-45b6-8dbe-7f924ed332bb");
		name = vertex.getString("name");
		assertEquals(name, "Volume_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix Volume");


		System.out.println("Testing Windows Volume ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:VolumeObj=\"http://cybox.mitre.org/objects#VolumeObject-2\" " + 
			"    xmlns:WinVolumeObj=\"http://cybox.mitre.org/objects#WinVolumeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-f74128d0-e162-48e7-bbbd-631d8606c262\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinVolumeObj:WindowsVolumeObjectType\"> " + 
			"                    <VolumeObj:Name>Volume_Name</VolumeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-f74128d0-e162-48e7-bbbd-631d8606c262");
		name = vertex.getString("name");
		assertEquals(name, "Volume_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Volume");


		System.out.println("Testing Volume ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:VolumeObj=\"http://cybox.mitre.org/objects#VolumeObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-aaa8c8e1-36a3-4ed4-a56b-670ff3f0a16d\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"VolumeObj:VolumeObjectType\"> " + 
			"                    <VolumeObj:Name>Volume_Name</VolumeObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-aaa8c8e1-36a3-4ed4-a56b-670ff3f0a16d");
		name = vertex.getString("name");
		assertEquals(name, "Volume_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Volume");


		System.out.println("Testing Whois ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:WhoisObj=\"http://cybox.mitre.org/objects#WhoisObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-8cc3cb1c-74be-4f5f-bb26-4d77c5cac3d6\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WhoisObj:WhoisObjectType\"> " + 
			"                    <WhoisObj:Domain_Name> " + 
			"                        <URIObj:Value>Domain_Name</URIObj:Value> " + 
			"                    </WhoisObj:Domain_Name> " + 
			"                    <WhoisObj:Server_Name> " + 
			"                        <URIObj:Value>Server_Name</URIObj:Value> " + 
			"                    </WhoisObj:Server_Name> " + 
			"                    <WhoisObj:IP_Address> " + 
			"                        <AddressObj:Address_Value>Address_Value</AddressObj:Address_Value> " + 
			"                    </WhoisObj:IP_Address> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-8cc3cb1c-74be-4f5f-bb26-4d77c5cac3d6");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-8cc3cb1c-74be-4f5f-bb26-4d77c5cac3d6");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Whois");

		System.out.println("Testing Windows Critical Section ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinCriticalSectionObj=\"http://cybox.mitre.org/objects#WinCriticalSectionObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-2415e5ed-6e4f-4b33-9fc2-065c09d6b317\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinCriticalSectionObj:WindowsCriticalSectionObjectType\"> " + 
			"                    <WinCriticalSectionObj:Address>Hex_Binary_Address</WinCriticalSectionObj:Address> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-2415e5ed-6e4f-4b33-9fc2-065c09d6b317");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-2415e5ed-6e4f-4b33-9fc2-065c09d6b317");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Critical Section");

		System.out.println("Testing Windows Event Log ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinEventLogObj=\"http://cybox.mitre.org/objects#WinEventLogObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-90133cd1-a1a1-43d7-b5a9-89464082d9f8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinEventLogObj:WindowsEventLogObjectType\"> " + 
			"                    <WinEventLogObj:EID>EID</WinEventLogObj:EID> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-90133cd1-a1a1-43d7-b5a9-89464082d9f8");
		name = vertex.getString("name");
		assertEquals(name, "EID");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Event Log");


		System.out.println("Testing Windows Event ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinEventObj=\"http://cybox.mitre.org/objects#WinEventObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-bb5438b5-2fdf-464a-8a08-2c4a38e8ee46\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinEventObj:WindowsEventObjectType\"> " + 
			"                    <WinEventObj:Name>Event_Name</WinEventObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-bb5438b5-2fdf-464a-8a08-2c4a38e8ee46");
		name = vertex.getString("name");
		assertEquals(name, "Event_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Event");

		System.out.println("Testing Windows Filemapping ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinFilemappingObj=\"http://cybox.mitre.org/objects#WinFilemappingObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-b77fdf7f-7453-43e5-852f-7e2848f89714\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinFilemappingObj:WindowsFilemappingObjectType\"> " + 
			"                    <WinFilemappingObj:Name>File_Mapping_Name</WinFilemappingObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-b77fdf7f-7453-43e5-852f-7e2848f89714");
		name = vertex.getString("name");
		assertEquals(name, "File_Mapping_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Filemapping");

		System.out.println("Testing Windows Handle ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinHandleObj=\"http://cybox.mitre.org/objects#WinHandleObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-fdefa0b1-69de-4190-904e-d6a2d18506d6\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinHandleObj:WindowsHandleObjectType\"> " + 
			"                    <WinHandleObj:ID>ID</WinHandleObj:ID> " + 
			"                    <WinHandleObj:Name>Handler_Name</WinHandleObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-fdefa0b1-69de-4190-904e-d6a2d18506d6");
		name = vertex.getString("name");
		assertEquals(name, "Handler_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Handle");

		System.out.println("Testing Windows Hook ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:LibraryObj=\"http://cybox.mitre.org/objects#LibraryObject-2\" " + 
			"    xmlns:WinHandleObj=\"http://cybox.mitre.org/objects#WinHandleObject-2\" " + 
			"    xmlns:WinHookObj=\"http://cybox.mitre.org/objects#WinHookObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-d0849c88-7a46-432b-aa09-988b94278eea\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinHookObj:WindowsHookObjectType\"> " + 
			"                    <WinHookObj:Handle> " + 
			"                        <WinHandleObj:ID>ID</WinHandleObj:ID> " + 
			"                        <WinHandleObj:Name>Handler_Name</WinHandleObj:Name> " + 
			"                    </WinHookObj:Handle> " + 
			"                    <WinHookObj:Hooking_Function_Name>Hooking_Function_Name</WinHookObj:Hooking_Function_Name> " + 
			"                    <WinHookObj:Hooking_Module> " + 
			"                        <LibraryObj:Name>Library_Name</LibraryObj:Name> " + 
			"                    </WinHookObj:Hooking_Module> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-d0849c88-7a46-432b-aa09-988b94278eea");
		name = vertex.getString("name");
		assertEquals(name, "Hooking_Function_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Hook");

		System.out.println("Testing Windows Kernel Hook ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinKernelHookObj=\"http://cybox.mitre.org/objects#WinKernelHookObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-98fe2371-672e-471b-9713-7d7a669e04aa\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinKernelHookObj:WindowsKernelHookObjectType\"> " + 
			"                    <WinKernelHookObj:Hooking_Module>Hooking_Nodule_Name</WinKernelHookObj:Hooking_Module> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-98fe2371-672e-471b-9713-7d7a669e04aa");
		name = vertex.getString("name");
		assertEquals(name, "Hooking_Nodule_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Kernel Hook");

		System.out.println("Testing Windows Kernel ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinKernelObj=\"http://cybox.mitre.org/objects#WinKernelObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-298b100b-5298-4440-acc4-9278f64521b8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinKernelObj:WindowsKernelObjectType\"/> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-298b100b-5298-4440-acc4-9278f64521b8");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-298b100b-5298-4440-acc4-9278f64521b8");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Kernel");

		System.out.println("Testing Windows Mutex ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:MutexObj=\"http://cybox.mitre.org/objects#MutexObject-2\" " + 
			"    xmlns:WinMutexObj=\"http://cybox.mitre.org/objects#WinMutexObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-9c799658-d8cb-4350-86e5-227099a484f8\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinMutexObj:WindowsMutexObjectType\"> " + 
			"                    <MutexObj:Name>Mutex_Name</MutexObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-9c799658-d8cb-4350-86e5-227099a484f8");
		name = vertex.getString("name");
		assertEquals(name, "Mutex_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Mutex");

		System.out.println("Testing Windows Network Share ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinNetworkShareObj=\"http://cybox.mitre.org/objects#WinNetworkShareObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-8f7b8673-2b7b-4fbd-9ffc-9918fe1ec4ec\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinNetworkShareObj:WindowsNetworkShareObjectType\"> " + 
			"                    <WinNetworkShareObj:Netname>Windows_Network_Name</WinNetworkShareObj:Netname> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-8f7b8673-2b7b-4fbd-9ffc-9918fe1ec4ec");
		name = vertex.getString("name");
		assertEquals(name, "Windows_Network_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Network Share");

		System.out.println("Testing Windows Prefetch ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinPrefetchObj=\"http://cybox.mitre.org/objects#WinPrefetchObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-983b843c-526f-4b44-9b02-8c5be5cd549a\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinPrefetchObj:WindowsPrefetchObjectType\"> " + 
			"                    <WinPrefetchObj:Application_File_Name>Application_File_Name</WinPrefetchObj:Application_File_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-983b843c-526f-4b44-9b02-8c5be5cd549a");
		name = vertex.getString("name");
		assertEquals(name, "Application_File_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Prefetch");

		System.out.println("Testing Windows Registry Key ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-6ecad031-a76a-4672-b6e3-dce6b8e57efe\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " + 
			"                    <WinRegistryKeyObj:Key>Key</WinRegistryKeyObj:Key> " + 
			"                    <WinRegistryKeyObj:Hive>Hive</WinRegistryKeyObj:Hive> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-6ecad031-a76a-4672-b6e3-dce6b8e57efe");
		name = vertex.getString("name");
		assertEquals(name, "Key");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Registry Key");

		System.out.println("Testing Windows System Restore ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinSystemRestoreObj=\"http://cybox.mitre.org/objects#WinSystemRestoreObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-35d58164-4eb3-4285-a7e9-94d466531c89\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinSystemRestoreObj:WindowsSystemRestoreObjectType\"> " + 
			"                    <WinSystemRestoreObj:Restore_Point_Name>Restore_Point_Name</WinSystemRestoreObj:Restore_Point_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-35d58164-4eb3-4285-a7e9-94d466531c89");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-35d58164-4eb3-4285-a7e9-94d466531c89");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows System Restore");

		System.out.println("Testing Windows Task ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinTaskObj=\"http://cybox.mitre.org/objects#WinTaskObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-d55859ea-0cb8-4c9c-b36d-9071ce6af518\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinTaskObj:WindowsTaskObjectType\"> " + 
			"                    <WinTaskObj:Name>Name</WinTaskObj:Name> " + 
			"                    <WinTaskObj:Application_Name>Application_Name</WinTaskObj:Application_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-d55859ea-0cb8-4c9c-b36d-9071ce6af518");
		name = vertex.getString("name");
		assertEquals(name, "Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Task");

		System.out.println("Testing Windows Thread ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinThreadObj=\"http://cybox.mitre.org/objects#WinThreadObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-a7fe91f8-68d6-410e-a935-19035c812b1f\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinThreadObj:WindowsThreadObjectType\"> " + 
			"                    <WinThreadObj:Thread_ID>ID</WinThreadObj:Thread_ID> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-a7fe91f8-68d6-410e-a935-19035c812b1f");
		name = vertex.getString("name");
		assertEquals(name, "ID");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Thread");

		System.out.println("Testing Windows User Account ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AccountObj=\"http://cybox.mitre.org/objects#AccountObject-2\" " + 
			"    xmlns:UserAccountObj=\"http://cybox.mitre.org/objects#UserAccountObject-2\" " + 
			"    xmlns:WinUserAccountObj=\"http://cybox.mitre.org/objects#WinUserAccountObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c492cfc9-28ca-4839-a97a-fd7dd4cb6271\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinUserAccountObj:WindowsUserAccountObjectType\"> " + 
			"                    <AccountObj:Domain>Domain</AccountObj:Domain> " + 
			"                    <UserAccountObj:Full_Name>Full_Name</UserAccountObj:Full_Name> " + 
			"                    <UserAccountObj:Username>Username</UserAccountObj:Username> " + 
			"                    <WinUserAccountObj:Security_ID>Security_ID</WinUserAccountObj:Security_ID> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c492cfc9-28ca-4839-a97a-fd7dd4cb6271");
		name = vertex.getString("name");
		assertEquals(name, "Username");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows User Account");

		System.out.println("Testing Unix User Account ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AccountObj=\"http://cybox.mitre.org/objects#AccountObject-2\" " + 
			"    xmlns:UnixUserAccountObj=\"http://cybox.mitre.org/objects#UnixUserAccountObject-2\" " + 
			"    xmlns:UserAccountObj=\"http://cybox.mitre.org/objects#UserAccountObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-88bb15ae-f84d-40d8-ac03-cad8e16c33e5\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixUserAccountObj:UnixUserAccountObjectType\"> " + 
			"                    <AccountObj:Domain>Domain</AccountObj:Domain> " + 
			"                    <UserAccountObj:Full_Name>Full_Name</UserAccountObj:Full_Name> " + 
			"                    <UserAccountObj:Username>Username</UserAccountObj:Username> " + 
			"                    <UnixUserAccountObj:Group_ID>Group_ID</UnixUserAccountObj:Group_ID> " + 
			"                    <UnixUserAccountObj:User_ID>User_ID</UnixUserAccountObj:User_ID> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-88bb15ae-f84d-40d8-ac03-cad8e16c33e5");
		name = vertex.getString("name");
		assertEquals(name, "Username");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Unix User Account");

		System.out.println("Testing Windows Waitable Timer ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinWaitableTimerObj=\"http://cybox.mitre.org/objects#WinWaitableTimerObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-c58e0eba-2a31-4d10-8e29-d9b56af323fa\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinWaitableTimerObj:WindowsWaitableTimerObjectType\"> " + 
			"                    <WinWaitableTimerObj:Name>Table_Name</WinWaitableTimerObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-c58e0eba-2a31-4d10-8e29-d9b56af323fa");
		name = vertex.getString("name");
		assertEquals(name, "Table_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Waitable Timer");

		System.out.println("Testing X509 Certificate ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:X509CertificateObj=\"http://cybox.mitre.org/objects#X509CertificateObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-abfc2845-0cae-4d11-9ecf-5f905bb21945\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"X509CertificateObj:X509CertificateObjectType\"> " + 
			"                    <X509CertificateObj:Certificate> " + 
			"                        <X509CertificateObj:Serial_Number>Serial_Number</X509CertificateObj:Serial_Number> " + 
			"                    </X509CertificateObj:Certificate> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-abfc2845-0cae-4d11-9ecf-5f905bb21945");
		name = vertex.getString("name");
		assertEquals(name, "Serial_Number");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "X509 Certificate");

		System.out.println("Testing Windows System ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinSystemObj=\"http://cybox.mitre.org/objects#WinSystemObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-bb1225d1-4e17-4dc0-8644-adbf394fef9c\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinSystemObj:WindowsSystemObjectType\"> " + 
			"                    <WinSystemObj:Product_ID>ID</WinSystemObj:Product_ID> " + 
			"                    <WinSystemObj:Product_Name>Product_Name</WinSystemObj:Product_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-bb1225d1-4e17-4dc0-8644-adbf394fef9c");
		name = vertex.getString("name");
		assertEquals(name, "Product_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows System");


		System.out.println("Testing Windows Driver ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinDriverObj=\"http://cybox.mitre.org/objects#WinDriverObject-3\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-0ef5a0a4-1ecb-491c-9643-42405338f428\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinDriverObj:WindowsDriverObjectType\"> " + 
			"                    <WinDriverObj:Driver_Name>Driver_Name</WinDriverObj:Driver_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-0ef5a0a4-1ecb-491c-9643-42405338f428");
		name = vertex.getString("name");
		assertEquals(name, "Driver_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Driver");


		System.out.println("Testing Windows Mailslot ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinMailslotObj=\"http://cybox.mitre.org/objects#WinMailslotObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-399e91a7-a38e-419f-a437-126d998da944\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinMailslotObj:WindowsMailslotObjectType\"> " + 
			"                    <WinMailslotObj:Name>Mailslot_Name</WinMailslotObj:Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-399e91a7-a38e-419f-a437-126d998da944");
		name = vertex.getString("name");
		assertEquals(name, "Mailslot_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Mailslot");


		System.out.println("Testing Windows Service ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:WinServiceObj=\"http://cybox.mitre.org/objects#WinServiceObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-2501125e-f5f9-4cac-900b-27e16b560cb9\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"WinServiceObj:WindowsServiceObjectType\"> " + 
			"                    <WinServiceObj:Service_Name>Windows_Service_Name</WinServiceObj:Service_Name> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-2501125e-f5f9-4cac-900b-27e16b560cb9");
		name = vertex.getString("name");
		assertEquals(name, "Windows_Service_Name");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Service");


		System.out.println("Testing Link ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:LinkObj=\"http://cybox.mitre.org/objects#LinkObject-1\" " + 
			"    xmlns:URIObj=\"http://cybox.mitre.org/objects#URIObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-bd3d9513-48c6-488f-a0f7-53bfbf50390e\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"LinkObj:LinkObjectType\"> " + 
			"                    <URIObj:Value>Link_Value</URIObj:Value> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-bd3d9513-48c6-488f-a0f7-53bfbf50390e");
		name = vertex.getString("name");
		assertEquals(name, "Link_Value");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Link");


		System.out.println("Testing User Account ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:UserAccountObj=\"http://cybox.mitre.org/objects#UserAccountObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-8b6b248c-1e51-4d63-9cf1-2226b781645c\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UserAccountObj:UserAccountObjectType\"> " + 
			"                    <UserAccountObj:Full_Name>Full_Name</UserAccountObj:Full_Name> " + 
			"                    <UserAccountObj:Username>Username</UserAccountObj:Username> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-8b6b248c-1e51-4d63-9cf1-2226b781645c");
		name = vertex.getString("name");
		assertEquals(name, "Username");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "User Account");


		System.out.println("Testing Address ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-633b417c-327f-4085-86ae-722ee26440bf\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\"> " + 
			"                    <AddressObj:Address_Value>Address_Value</AddressObj:Address_Value> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-633b417c-327f-4085-86ae-722ee26440bf");
		name = vertex.getString("name");
		assertEquals(name, "Address_Value");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Address");


		System.out.println("Testing Email Message ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:EmailMessageObj=\"http://cybox.mitre.org/objects#EmailMessageObject-2\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-8d5c1efd-d5f8-489d-b2cb-f400f924f800\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"EmailMessageObj:EmailMessageObjectType\"> " + 
			"                    <EmailMessageObj:Header> " + 
			"                        <EmailMessageObj:Subject>Subject</EmailMessageObj:Subject> " + 
			"                    </EmailMessageObj:Header> " + 
			"                    <EmailMessageObj:Raw_Body>Raw_Body</EmailMessageObj:Raw_Body> " + 
			"                    <EmailMessageObj:Raw_Header>Raw_Header</EmailMessageObj:Raw_Header> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-8d5c1efd-d5f8-489d-b2cb-f400f924f800");
		name = vertex.getString("name");
		assertEquals(name, "Raw_Body");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Email Message");

		System.out.println("Testing Socket Address ...");
		stix =   
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " + 
			"    xmlns:HostnameObj=\"http://cybox.mitre.org/objects#HostnameObject-1\" " + 
			"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " + 
			"    xmlns:SocketAddressObj=\"http://cybox.mitre.org/objects#SocketAddressObject-1\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable id=\"stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Object> " + 
			"                <cybox:Properties " + 
			"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"SocketAddressObj:SocketAddressObjectType\"> " + 
			"                    <SocketAddressObj:Hostname> " + 
			"                        <HostnameObj:Hostname_Value>Hostname</HostnameObj:Hostname_Value> " + 
			"                    </SocketAddressObj:Hostname> " + 
			"                    <SocketAddressObj:IP_Address> " + 
			"                        <AddressObj:Address_Value>100.100.100.100</AddressObj:Address_Value> " + 
			"                    </SocketAddressObj:IP_Address> " + 
			"                    <SocketAddressObj:Port> " + 
			"                        <PortObj:Port_Value>80</PortObj:Port_Value> " + 
			"                    </SocketAddressObj:Port> " + 
			"                </cybox:Properties> " + 
			"            </cybox:Object> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);

		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f");
		name = vertex.getString("name");
		assertEquals(name, "100.100.100.100:80");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Socket Address");
	
			System.out.println("Testing Network Subnet ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables> " + 
			"        <cybox:Observable " + 
			"            id=\"stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f\" xmlns:stucco=\"gov.ornl.stucco\"> " + 
			"            <cybox:Event> " + 
			"                <cybox:Actions> " + 
			"                    <cybox:Action> " + 
			"                        <cybox:Name>Action_Name</cybox:Name> " + 
			"                        <cybox:Description>Action_Description</cybox:Description> " + 
			"                    </cybox:Action> " + 
			"                </cybox:Actions> " + 
			"            </cybox:Event> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Event");
	
		System.out.println("Testing Observable Composition ...");
		stix =  
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " + 
			"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " + 
			"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" xmlns:stix=\"http://stix.mitre.org/stix-1\"> " + 
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " + 
			"        <cybox:Observable " +
			"            id=\"stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f\" xmlns:stucco=\"gov.ornl.stucco\"> " +  
			"            <cybox:Observable_Composition> " + 
			"                <cybox:Observable " + 
			"                    idref=\"stucco:Observable-abd2ae66-be08-43e6-a66d-eec294c1d210\" xmlns:stucco=\"gov.ornl.stucco\"/> " + 
			"                <cybox:Observable " + 
			"                    idref=\"stucco:Observable-9438e492-3f93-444b-a159-216f32db4bef\" xmlns:stucco=\"gov.ornl.stucco\"/> " + 
			"            </cybox:Observable_Composition> " + 
			"        </cybox:Observable> " + 
			"    </stix:Observables> " + 
			"</stix:STIX_Package> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f");
		name = vertex.getString("name");
		assertEquals(name, "stucco:Observable-cbd0ef95-cf60-4f58-9b86-6a87107bb85f");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Observable Composition");
		
		System.out.println("Testing Observable Composition ...");
		stix =  
			"  <cybox:Observables xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
			"   xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
			"   xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
			"   xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " +
			"   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
			"   xmlns:example=\"http://example.com/\" " +
			"   cybox_major_version=\"2\"  " +
			"   cybox_minor_version=\"1\"> " +
			"     <cybox:Observable id=\"example:f6bb0360-46ac-49b9-9ca1-9008e937ea24\"> " +
			"         <cybox:Observable_Composition operator=\"AND\"> " +
			"            <cybox:Observable id=\"example:ca588488-5900-401e-b02f-0080d83e2472\"> " +
			"               <cybox:Object> " +
			"                  <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
			"                     <FileObj:File_Path condition=\"Contains\" fully_qualified=\"false\">system32\twext.exe</FileObj:File_Path> " +
			"                     <FileObj:File_Name>twext.exe</FileObj:File_Name> " +
			"                  </cybox:Properties> " +
			"               </cybox:Object> " +
			"            </cybox:Observable> " +
			"            <cybox:Observable id=\"example:b1fc168c-c9be-4b4a-925e-206b9afed76a\"> " +
			"               <cybox:Object> " +
			"                  <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
			"                     <WinRegistryKeyObj:Key condition=\"Equals\">Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon</WinRegistryKeyObj:Key> " +
			"                     <WinRegistryKeyObj:Hive condition=\"Equals\">HKEY_LOCAL_MACHINE</WinRegistryKeyObj:Hive> " +
			"                     <WinRegistryKeyObj:Values> " +
			"                        <WinRegistryKeyObj:Value> " +
			"                           <WinRegistryKeyObj:Name condition=\"Equals\">Userinit</WinRegistryKeyObj:Name> " +
			"                           <WinRegistryKeyObj:Data condition=\"Contains\">system32\\twext.exe</WinRegistryKeyObj:Data> " +
			"                        </WinRegistryKeyObj:Value> " +
			"                     </WinRegistryKeyObj:Values> " +
			"                  </cybox:Properties> " +
			"               </cybox:Object> " +
			"            </cybox:Observable> " +
			"         </cybox:Observable_Composition> " +
			"      </cybox:Observable> " +
			"  </cybox:Observables> ";
		stixElements = preprocessSTIX.normalizeSTIX(stix);
		graph = graphConstructor.constructGraph(stixElements);
		
		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("example:f6bb0360-46ac-49b9-9ca1-9008e937ea24");
		name = vertex.getString("name");
		assertEquals(name, "example:f6bb0360-46ac-49b9-9ca1-9008e937ea24");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Observable Composition");

		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("example:ca588488-5900-401e-b02f-0080d83e2472");
		name = vertex.getString("name");
		assertEquals(name, "twext.exe");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "File");

		vertices = graph.getJSONObject("vertices");	
		vertex = vertices.getJSONObject("example:b1fc168c-c9be-4b4a-925e-206b9afed76a");
		name = vertex.getString("name");
		assertEquals(name, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
		observableType = vertex.getString("observableType");
		assertEquals(observableType, "Windows Registry Key");
		
	}

	@Test
	public void test_large_file() {
		try {
			java.nio.file.Path path = java.nio.file.Paths.get("output.xml");
			String info = new String(java.nio.file.Files.readAllBytes(path));

			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Vertex> stixElements = preprocessSTIX.normalizeSTIX(info);
			
			GraphConstructor graphConstructor = new GraphConstructor();
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			System.out.println(graph.toString(2));

			JSONObject vertices = graph.getJSONObject("vertices");
			System.out.println("vertices size: " + vertices.length());
			JSONArray edges = graph.getJSONArray("edges");
			System.out.println("edges size: " + edges.length());
		}	catch (java.io.IOException e) {
			e.printStackTrace();
		}
	}
}
