package alignment.alignment_v2;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

import org.jdom2.xpath.*;
import org.jdom2.*;

import org.mitre.stix.stix_1.STIXPackage;

/**
 * Unit test for STIX GraphConstructor
 */
public class GraphConstructorTest extends PreprocessSTIXwithJDOM2 {

	String[] allVerts = {"Account", "Organization", "Address", "AddressRange", "Port", "DNSName", "Malware", "Exploit", "HTTPRequest", "DNSRecord", "IP", "Service", "Host", "Vulnerability", "Flow", "AS", "Software"};

	@Test 
	public void testVulnerabilityExploit() {

		System.out.println("RUNNING: GraphConstructorTest.testVulnerabilityExploit()");

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
			"                        <ttp:Description>This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.</ttp:Description>"+
			"                        <ttp:Short_Description>AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow</ttp:Short_Description>"+
			"                    </ttp:Exploit>"+
			"                </ttp:Exploits>"+
			"            </ttp:Behavior>"+
			"            <ttp:Exploit_Targets>"+
			"                <ttp:Exploit_Target>"+
			"                    <stixCommon:Relationship>Exploits</stixCommon:Relationship>"+
			"                    <stixCommon:Exploit_Target xsi:type=\"et:ExploitTargetType\"> "+
			"            		<et:Title>Vulnerability</et:Title>"+
			"            		<et:Vulnerability>"+
			"                		<et:Description>CVE-2009-3699</et:Description>"+
			"                		<et:CVE_ID>CVE-2009-3699</et:CVE_ID>"+
			"                		<et:Source>Metasploit</et:Source>"+
			"            		</et:Vulnerability>"+
			"		     </stixCommon:Exploit_Target>" +
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
			"</stix:STIX_Package>";
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testMalwareIP() {
		
		System.out.println("RUNNING: GraphConstructorTest.testMalwareIP()");
		
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
			"                        <cybox:Observable>"+
			"            		    <cybox:Title>IP</cybox:Title>"+
			"            		    <cybox:Observable_Source>"+
			"                		<cyboxCommon:Information_Source_Type>1d4.us</cyboxCommon:Information_Source_Type>"+
			"            			</cybox:Observable_Source>"+
			"            			<cybox:Object id=\"stucco:ip-1730444733\">"+
			"                		    <cybox:Description>103.36.125.189</cybox:Description>"+
			"                		    <cybox:Properties category=\"ipv4-addr\""+
			"                    		xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AddressObj:AddressObjectType\">"+
			"                    		<AddressObj:Address_Value>103.36.125.189</AddressObj:Address_Value>"+
			"                		</cybox:Properties>"+
			"            		    </cybox:Object>"+
			"			 </cybox:Observable>" +
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
	
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}		
	
//	@Test 
	public void testFlowAddressIpPort() {
		
		System.out.println("RUNNING: GraphConstructorTest.testFlowAddressIpPort()");
		
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

		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}		
	
//	@Test 
	public void testOrganizationAddressRangeAS() {
		
		System.out.println("RUNNING: GraphConstructorTest.testOrganizationAddressRangeAS()");
		
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
			"                            <cyboxCommon:Information_Source_Type>Caida</cyboxCommon:Information_Source_Type>"+
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
			"                            <cyboxCommon:Information_Source_Type>Caida</cyboxCommon:Information_Source_Type>"+
			"                        </cybox:Discovery_Method>"+
			"                        <cybox:Relationship>Has_AS</cybox:Relationship>"+
			"                    </cybox:Related_Object>"+
			"                </cybox:Related_Objects>"+
			"            </cybox:Object>"+
			"        </cybox:Observable>"+
			"    </stix:Observables>"+
			"</stix:STIX_Package>";
		
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testSoftware() {
		
		System.out.println("RUNNING: GraphConstructorTest.testSoftware()");
		
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
		
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testDNSRecordIpDNSName() {
		
		System.out.println("RUNNING: GraphConstructorTest.testDNSRecordIpDNSName()");
		
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
		
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testServicePort() {
		
		System.out.println("RUNNING: GraphConstructorTest.testServicePort()");
		
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
		
		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testHTTPRequestIpPortDNSName() {
		
		System.out.println("RUNNING: GraphConstructorTest.testHTTPRequestIpPortDNSName()");
		
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

		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testHostSoftware() {
		
		System.out.println("RUNNING: GraphConstructorTest.testHostSoftware()");
		
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

		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
	
//	@Test 
	public void testHostSoftwareAccountIp() {
		
		System.out.println("RUNNING: GraphConstructorTest.testHostSoftwareAccountIp()");
		
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
			"                <cybox:Description>host_at_192.168.10.11</cybox:Description>"+
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

		STIXPackage pack = new STIXPackage().fromXMLString(stix);
		assertTrue(validate(pack));
		GraphConstructor graphConstructor = new GraphConstructor();
		graphConstructor.constructGraph(stix);
		assertTrue(true);
	}
}
