package gov.ornl.stucco.alignment;

import gov.ornl.stucco.alignment.Align;
import gov.ornl.stucco.alignment.DBConnectionJson;
import gov.ornl.stucco.alignment.GraphConstructor;
import gov.ornl.stucco.alignment.PreprocessSTIX;
import gov.pnnl.stucco.dbconnect.Condition;
import gov.pnnl.stucco.dbconnect.DBConstraint;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Collection; 

import org.junit.Test;

import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray; 
import org.mitre.stix.stix_1.STIXPackage; 

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

/**
 * Unit test for STIX Align
 */ 
public class AlignTest {

			
	private static boolean compareJSONObjects (JSONObject object1, JSONObject object2)	{

		if (object1 == null && object2 != null) return false;
		if (object1 != null && object2 == null) return false;			

		List<String> keysArray1 = new ArrayList<String>();
		List<String> keysArray2 = new ArrayList<String>();

		Iterator<String> keys1 = object1.keys();
		while(keys1.hasNext())	
			keysArray1.add(keys1.next());
		
		Iterator<String> keys2 = object2.keys();
		while(keys2.hasNext())	
			keysArray2.add(keys2.next());
									
		if (keysArray1.size() != keysArray2.size())	return false;
					
		for (String key: keysArray1)	{
			if (!object2.has(key)) return false; 
		}

		for (int i = 0; i < keysArray1.size(); i++)	{
			String key = keysArray1.get(i);
			if (compare(object1.get(key), object2.get(key)) == false) return false;
		}
						
		return true;
	}
						
	private static boolean compareJSONArrays(JSONArray array1, JSONArray array2)	{
		
		if (array1 == null && array2 != null) return false;
		if (array1 != null && array2 == null) return false;			
		if (array1.length() != array2.length())	return false;

		for (int i = 0; i < array1.length(); i++)	{
			Object o1 = array1.get(i);
			boolean equals = false;
			for (int j = 0; j < array2.length(); j++)	{
				Object o2 = array2.get(j);
				equals = compare(o1, o2);
				if (equals == true) break;
			}
			if (equals == false)	return false;
		}
		return true;

	}
			
	private static boolean compare(Object object1, Object object2)	{
									
		if (object1 instanceof JSONArray && object2  instanceof JSONArray)	
			return compareJSONArrays((JSONArray)object1, (JSONArray)object2);
																		
		else if (object1 instanceof JSONObject && object2 instanceof JSONObject)	
			return compareJSONObjects((JSONObject)object1, (JSONObject)object2);
		
		else	return object1.toString().equals(object2.toString());
	}

	/**
	 * Parses xml String and converts it to jdom2 Document
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

	public void jsonArrayToSetConverter(JSONObject graph) {
		JSONObject verts = graph.getJSONObject("vertices");
		for (Object id : verts.keySet()) {
			JSONObject v = verts.getJSONObject(id.toString());
			for (Object key : v.keySet()) {
				if (v.get(key.toString()) instanceof JSONArray) {
					Set<Object> set = new HashSet<Object>();
					JSONArray array = v.getJSONArray(key.toString());
					for (int i = 0; i < array.length(); i++) {
						set.add(array.get(i));
					}
					v.put(key.toString(), (Object)set);
				}
			}
		}
	}

	@Test 
	public void testStixIDUpdate() {
		System.out.println("[RUNNING:] alignment.alignment_v2.testStixIDUpdate()");
		String graphString1 = 
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
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"Observable-ef0e7868-0d1f-4f56-kkkk-83hgkdbvktos\">"+
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
			"</stix:STIX_Package>";	

		String graphString2 = 
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

		try {
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			GraphConstructor graphConstructor = new GraphConstructor();
			Align align = new Align();
			DBConnectionJson db = align.getConnection();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(graphString1);
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			stixElements = preprocessSTIX.normalizeSTIX(graphString2);
			graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			JSONObject malware = db.getVertByName("Scanner");
			String sourceDocument = malware.getString("sourceDocument");
			Element malwareXml = parseXMLText(sourceDocument).getRootElement();
			Element resources = malwareXml.getChild("Resources", Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1"));
			Element infrastructure = resources.getChild("Infrastructure", Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1"));		
			Element observableCharacterization = infrastructure.getChild("Observable_Characterization", Namespace.getNamespace("ttp", "http://stix.mitre.org/TTP-1"));
			Element observable = observableCharacterization.getChild("Observable", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			String idref = observable.getAttributeValue("idref");
			assertEquals(idref, "Observable-ef0e7868-0d1f-4f56-kkkk-83hgkdbvktos");
			long vertsCount = db.getVertCount();
			assertEquals(vertsCount, 2);
			long edgeCount = db.getEdgeCount();
			assertEquals(edgeCount, 1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testDuplicateIPByName() {
		System.out.println("[RUNNING:] alignment.alignment_v2.testDuplicateIPByName()");

		String graphString1 = 
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
			"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\">"+
			"        <cybox:Observable id=\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229\">"+
			"            <cybox:Title>IP</cybox:Title>"+
			"            <cybox:Observable_Source>"+
			"                <cyboxCommon:Information_Source_Type>GeoIP</cyboxCommon:Information_Source_Type>"+
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
			"</stix:STIX_Package>";	

		String graphString2 = 
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
			"</stix:STIX_Package>";	
	
		try {
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			GraphConstructor graphConstructor = new GraphConstructor();
			Align align = new Align();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			DBConnectionJson db = align.getConnection();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(graphString1);
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			stixElements = preprocessSTIX.normalizeSTIX(graphString2);
			graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			assertTrue(db.getVertCount() == 1);
			JSONObject vulnerability = db.getVertByName("103.36.125.189");
			assertEquals(vulnerability.getString("vertexType"), "IP");
			Set<Object> descriptionSet = (HashSet<Object>) vulnerability.get("description");
			assertTrue(descriptionSet.contains("103.36.125.189"));
			Set<Object> sourceSet = (HashSet<Object>) vulnerability.get("source");
			assertTrue(sourceSet.contains("1d4.us"));
			assertTrue(sourceSet.contains("GeoIP"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testDuplicateVulnerabilityByType() {
		System.out.println("[RUNNING:] alignment.alignment_v2.testDuplicateVulnerabilityByType()");

		String graphString1 = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:metasploit-2e579a0a-0c44-4311-b6f0-a8fee86c3949\""+
			"    timestamp=\"2015-12-07T23:26:28.613Z\""+
			"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\""+
			"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">"+
			"    <stix:Exploit_Targets>"+
			"        <stixCommon:Exploit_Target"+
			"            id=\"Exploit_Target-13770b0f-fcd6-416a-9e43-2da475797716\""+
			"            xmlns=\"\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\">"+
			"            <et:Title>Vulnerability</et:Title>"+
			"            <et:Vulnerability>"+
			"                <et:Description>Bufer overflow in bicsa.a in IBM.</et:Description>"+
			"                <et:Description>Bufer overflow.</et:Description>"+
			"                <et:CVE_ID>CVE-2009-3699</et:CVE_ID>"+
			"                <et:Source>NVD</et:Source>"+
			"            </et:Vulnerability>"+
			"        </stixCommon:Exploit_Target>"+
			"    </stix:Exploit_Targets>"+
			"</stix:STIX_Package>";

		String graphString2 = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
			"<stix:STIX_Package"+
			"    id=\"stucco:metasploit-2e579a0a-0c44-4311-b6f0-a8fee86c3949\""+
			"    timestamp=\"2015-12-07T23:26:28.613Z\""+
			"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\""+
			"    xmlns:stix=\"http://stix.mitre.org/stix-1\""+
			"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\""+
			"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\">"+
			"    <stix:Exploit_Targets>"+
			"        <stixCommon:Exploit_Target"+
			"            id=\"Exploit_Target-13770b0f-fcd6-416a-9e43-2da475111900\""+
			"            xmlns=\"\""+
			"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\">"+
			"            <et:Title>Vulnerability</et:Title>"+
			"            <et:Vulnerability>"+
			"                <et:Description>Bufer overflow in IBM AIX 5.x in bicsa.a.</et:Description>"+
			"                <et:Source>Metasploit</et:Source>"+
			"            </et:Vulnerability>"+
			"        </stixCommon:Exploit_Target>"+
			"    </stix:Exploit_Targets>"+
			"</stix:STIX_Package>";
	
		try {
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			GraphConstructor graphConstructor = new GraphConstructor();
			Align align = new Align();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			DBConnectionJson db = align.getConnection();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(graphString1);
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			stixElements = preprocessSTIX.normalizeSTIX(graphString2);
			graph = graphConstructor.constructGraph(stixElements);
			align.load(graph);
			JSONObject vulnerability = db.getVertByName("CVE-2009-3699");
			assertEquals(vulnerability.getString("vertexType"), "Vulnerability");
			Set<Object> descriptionSet = (HashSet<Object>) vulnerability.get("description");
			assertTrue(descriptionSet.contains("Bufer overflow in IBM AIX 5.x in bicsa.a."));
			assertTrue(descriptionSet.contains("Bufer overflow in bicsa.a in IBM."));
			assertTrue(descriptionSet.contains("Bufer overflow."));
			Set<Object> sourceSet = (HashSet<Object>) vulnerability.get("source");
			assertTrue(sourceSet.contains("NVD"));
			assertTrue(sourceSet.contains("Metasploit"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testDuplicateMalwareByAlias() {
		System.out.println("[RUNNING:] alignment.alignment_v2.testDuplicateMalwareByAlias()");

		String graph1 = 
			"{\"vertices\": {\"stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3\": { " +
			"  \"sourceDocument\": \"<ttp:TTP xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" id=\\\"stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3\\\" xsi:type=\\\"ttp:TTPType\\\"><ttp:Title>Malware<\\/ttp:Title><ttp:Behavior><ttp:Malware><ttp:Malware_Instance id=\\\"stucco:malware-scanner\\\"><ttp:Type>Scanner<\\/ttp:Type><ttp:Name>Scanner Name<\\/ttp:Name><ttp:Title>Scanner<\\/ttp:Title><ttp:Description>Scanner Description1<\\/ttp:Description><\\/ttp:Malware_Instance><\\/ttp:Malware><\\/ttp:Behavior><ttp:Resources><ttp:Infrastructure><ttp:Observable_Characterization cybox_major_version=\\\"2.0\\\" cybox_minor_version=\\\"1.0\\\"><cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" idref=\\\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229\\\" /><\\/ttp:Observable_Characterization><\\/ttp:Infrastructure><\\/ttp:Resources><ttp:Information_Source><stixCommon:Contributing_Sources xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\"><stixCommon:Source><stixCommon:Identity><stixCommon:Name>1d4.us<\\/stixCommon:Name><\\/stixCommon:Identity><\\/stixCommon:Source><\\/stixCommon:Contributing_Sources><\\/ttp:Information_Source><\\/ttp:TTP>\", " +
			"  \"vertexType\": \"Malware\", " +
			"  \"name\": \"Scanner Name\", " +
			"  \"description\": [\"Scanner Description1\"], " +
			"  \"source\": [\"1d4.us\"] " +
			"}}} ";

		String graph2 = 
			"{\"vertices\": {\"stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc4\": { " +
			"  \"sourceDocument\": \"<ttp:TTP xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\" xmlns:stucco=\\\"gov.ornl.stucco\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" id=\\\"stucco:malware-2cbe5820-572c-493f-8008-7cb7bf344dc3\\\" xsi:type=\\\"ttp:TTPType\\\"><ttp:Title>Malware<\\/ttp:Title><ttp:Behavior><ttp:Malware><ttp:Malware_Instance id=\\\"stucco:malware-scanner\\\"><ttp:Type>Scanner<\\/ttp:Type><ttp:Name>Scanner<\\/ttp:Name><ttp:Name>Scanner Alias<\\/ttp:Name><ttp:Name>Scanner Name<\\/ttp:Name><ttp:Title>Scanner Description<\\/ttp:Title><ttp:Description>Scanner Description2<\\/ttp:Description><\\/ttp:Malware_Instance><\\/ttp:Malware><\\/ttp:Behavior><ttp:Resources><ttp:Infrastructure><ttp:Observable_Characterization cybox_major_version=\\\"2.0\\\" cybox_minor_version=\\\"1.0\\\"><cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" idref=\\\"Observable-ef0e7868-0d1f-4f56-ab90-b8ecfea62229\\\" /><\\/ttp:Observable_Characterization><\\/ttp:Infrastructure><\\/ttp:Resources><ttp:Information_Source><stixCommon:Contributing_Sources xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\"><stixCommon:Source><stixCommon:Identity><stixCommon:Name>Source<\\/stixCommon:Name><\\/stixCommon:Identity><\\/stixCommon:Source><\\/stixCommon:Contributing_Sources><\\/ttp:Information_Source><\\/ttp:TTP>\", " +
			"  \"vertexType\": \"Malware\", " +
			"  \"name\": \"Scanner\", " +
			"  \"description\": [\"Scanner Description2\"], " +
			"  \"alias\": [ " +
			"    \"Scanner Name\", " +
			"    \"Scanner Alias\" " +
			"  ], " +
			"  \"source\": [\"Source\"] " +
			"}}} ";

		try {
			Align align = new Align();
			DBConnectionJson db = align.getConnection();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			JSONObject graph = new JSONObject(graph1);
			jsonArrayToSetConverter(graph);
			align.load(graph);
			graph = new JSONObject(graph2);
			jsonArrayToSetConverter(graph);
			align.load(graph);

			JSONObject malware = db.getVertByName("Scanner Name");
			assertEquals(malware.getString("vertexType"), "Malware");
			Set<Object> descriptionSet = (HashSet<Object>) malware.get("description");
			assertTrue(descriptionSet.contains("Scanner Description1"));
			assertTrue(descriptionSet.contains("Scanner Description2"));
			Set<Object> sourceSet = (HashSet<Object>) malware.get("source");
			assertTrue(sourceSet.contains("1d4.us"));
			assertTrue(sourceSet.contains("Source"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test 
	public void testDuplicateIndicatorByAlias() {
		System.out.println("[RUNNING:] alignment.alignment_v2.testDuplicateIndicatorByAlias()");

		String graph1 = 
			"{\"vertices\": {\"fireeye:indicator-0036bca2-8c0a-4f09-934d-89a98fc41850\": { " +
			"    \"sourceDocument\": \"<indicator:Indicator xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\" xmlns:fireeye=\\\"http://www.fireeye.com\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" timestamp=\\\"2015-05-15T09:00:00.000000Z\\\" id=\\\"fireeye:indicator-0036bca2-8c0a-4f09-934d-89a98fc41850\\\" xsi:type=\\\"indicator:IndicatorType\\\"><indicator:Title>Domain: microsoftupdate.ns01.biz<\\/indicator:Title><indicator:Type xmlns:stixVocabs=\\\"http://stix.mitre.org/default_vocabularies-1\\\" xsi:type=\\\"stixVocabs:IndicatorTypeVocab-1.1\\\">Domain Watchlist<\\/indicator:Type><indicator:Observable idref=\\\"fireeye:observable-915b7cb4-e520-48dd-9273-1bdb4e71a823\\\" /><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-e55c6eaa-bf0f-4b6b-9572-5cd0d3f62134\\\" /><\\/indicator:Indicated_TTP><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-59fae6a2-4a3b-418e-8ca7-06a845820666\\\" /><\\/indicator:Indicated_TTP><indicator:Suggested_COAs><indicator:Suggested_COA><stixCommon:Course_Of_Action xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:courseofaction-70b3d5f6-374b-4488-8688-729b6eedac5b\\\" /><\\/indicator:Suggested_COA><\\/indicator:Suggested_COAs><\\/indicator:Indicator>\", " +
			"    \"vertexType\": \"Indicator\", " +
			"    \"name\": \"fireeye:indicator-0036bca2-8c0a-4f09-934d-89a98fc41850\", " +
			"    \"alias\": [ " +
			"      \"c1bcc9513f27c33d24f7ed0fc5700b47\", " +
			"      \"fireeye:courseofaction-70b3d5f6-374b-4488-8688-729b6eedac5b\", " +
			"      \"a144440d16fb69cf4522f789aacb3ef2\", " +
			"      \"microsoftupdate.ns01.biz\" " +
			"    ] " +
			"}}} ";

		String graph2 = 
			"{\"vertices\": {\"fireeye:indicator-b62b4960-e82e-4f91-9306-72086cc92e3f\": { " +
			"    \"sourceDocument\": \"<indicator:Indicator xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\" xmlns:fireeye=\\\"http://www.fireeye.com\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" timestamp=\\\"2015-05-15T09:00:00.000000Z\\\" id=\\\"fireeye:indicator-b62b4960-e82e-4f91-9306-72086cc92e3f\\\" xsi:type=\\\"indicator:IndicatorType\\\"><indicator:Title>Domain: pansenes.3322.org<\\/indicator:Title><indicator:Type xmlns:stixVocabs=\\\"http://stix.mitre.org/default_vocabularies-1\\\" xsi:type=\\\"stixVocabs:IndicatorTypeVocab-1.1\\\">Domain Watchlist<\\/indicator:Type><indicator:Observable idref=\\\"fireeye:observable-7c035577-8446-428c-ab4c-fe7359fde735\\\" /><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-5a74a069-0759-4c93-8ea3-70c53a223230\\\" /><\\/indicator:Indicated_TTP><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-3f39dad8-de02-468d-bd4b-de7ad4a4e357\\\" /><\\/indicator:Indicated_TTP><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-534b451e-a5ee-4264-89a0-b57cd2d9a21d\\\" /><\\/indicator:Indicated_TTP><indicator:Indicated_TTP><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:ttp-7781ffbf-2a5c-4a54-a489-2fddd85b7363\\\" /><\\/indicator:Indicated_TTP><indicator:Suggested_COAs><indicator:Suggested_COA><stixCommon:Course_Of_Action xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" idref=\\\"fireeye:courseofaction-70b3d5f6-374b-4488-8688-729b6eedac5b\\\" /><\\/indicator:Suggested_COA><\\/indicator:Suggested_COAs><\\/indicator:Indicator>\", " +
			"    \"vertexType\": \"Indicator\", " +
			"    \"name\": \"fireeye:indicator-b62b4960-e82e-4f91-9306-72086cc92e3f\", " +
			"    \"alias\": [ " +
			"      \"c1bcc9513f27c33d24f7ed0fc5700b47\", " +
			"      \"fireeye:courseofaction-70b3d5f6-374b-4488-8688-729b6eedac5b\", " +
			"      \"a144440d16fb69cf4522f789aacb3ef2\", " +
			"      \"36cc4c909462db0f067b11a5e719a4ee\", " +
			"      \"pansenes.3322.org\", " +
			"      \"a5ec5a677346634a42c9f9101ce9d861\" " +
			"    ] " +
			"  }, " +
			"}}} ";

		try {
			Align align = new Align();
			DBConnectionJson db = align.getConnection();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			JSONObject graph = new JSONObject(graph1);
			jsonArrayToSetConverter(graph);
			align.load(graph);
			graph = new JSONObject(graph2);
			jsonArrayToSetConverter(graph);
			align.load(graph);

			assertNull(db.getVertByName("fireeye:indicator-b62b4960-e82e-4f91-9306-72086cc92e3f"));
			JSONObject indicator = db.getVertByName("fireeye:indicator-0036bca2-8c0a-4f09-934d-89a98fc41850");
			assertEquals(indicator.getString("vertexType"), "Indicator");
			Set<Object> aliasSet = (HashSet<Object>) indicator.get("alias");
			assertTrue(aliasSet.contains("c1bcc9513f27c33d24f7ed0fc5700b47"));
			assertTrue(aliasSet.contains("fireeye:courseofaction-70b3d5f6-374b-4488-8688-729b6eedac5b"));
			assertTrue(aliasSet.contains("a144440d16fb69cf4522f789aacb3ef2"));
			assertTrue(aliasSet.contains("36cc4c909462db0f067b11a5e719a4ee"));
			assertTrue(aliasSet.contains("pansenes.3322.org"));
			assertTrue(aliasSet.contains("a5ec5a677346634a42c9f9101ce9d861"));
			assertTrue(aliasSet.contains("fireeye:indicator-b62b4960-e82e-4f91-9306-72086cc92e3f"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testEdgeLoad() {
		System.out.println("[Running] alignment.alignment_v2.AlignTest.testEdgeLoad()");

		String graphString = 
			"{"+
			"  \"vertices\": {"+
			"    \"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\": {"+
			"      \"endIP\": \"216.98.188.255\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\\\"><cybox:Title>AddressRange<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:addressRange-3630349312-3630349567\\\"><cybox:Description>216.98.188.0 through 216.98.188.255<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" apply_condition=\\\"ANY\\\" condition=\\\"InclusiveBetween\\\" delimiter=\\\" - \\\">216.98.188.0 - 216.98.188.255<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AddressRange\","+
			"      \"startIP\": \"216.98.188.0\","+
			"      \"startIPInt\": 3630349312,"+
			"      \"name\": \"216.98.188.0 - 216.98.188.255\","+
			"      \"description\": [\"216.98.188.0 through 216.98.188.255\"],"+
			"      \"source\": \"CAIDA\","+
			"      \"endIPInt\": 3630349567,"+
			"      \"observableType\": \"Address\""+
			"    },"+
			"    \"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\": {"+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\\\"><cybox:Title>IP<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">LoginEvent<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-3232238091\\\"><cybox:Description>192.168.10.11<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\">216.98.188.1<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"IP\","+
			"      \"ipInt\": 3630349313,"+
			"      \"name\": \"216.98.188.1\","+
			"      \"description\": \"216.98.188.1\","+
			"      \"source\": [\"LoginEvent\"],"+
			"      \"observableType\": \"Address\""+
			"    }" +
			"  }" +
			"}";
		
		try {
			JSONObject graph = new JSONObject(graphString);
			Align align = new Align();
			align.load(graph);
			DBConnectionJson db = align.getConnection();
			JSONObject vert = null;
			JSONObject originalVert = null;

			/* testing AddressRange */
			System.out.println("Testing AddressRange ...");
			vert = db.getVertByName("216.98.188.0 - 216.98.188.255");
			assertNotNull(vert);
			originalVert = db.getVertByName("216.98.188.0 - 216.98.188.255");
			assertTrue(compareJSONObjects(vert, originalVert));
			
			/* testing IP */
			System.out.println("Testing AddressRange ... ");
			vert = db.getVertByName("216.98.188.1");
			assertNotNull(vert);
			originalVert = db.getVertByName("216.98.188.1");
			assertTrue(compareJSONObjects(vert, originalVert));
			
			String outVertID = null;
			String inVertID = null;
			//List<String> edgeIDList = null;
			//String edgeID = null;
			//JSONObject edge = null;
			//JSONObject originalEdge = null;
			/* testing IP -> AddressRange edge */
			System.out.println("Testing IP -> Contained_Within -> AddressRange edge ...");
			inVertID = db.getVertIDByName("216.98.188.0 - 216.98.188.255");
			outVertID = db.getVertIDByName("216.98.188.1");
			int edgeIDCount = db.getEdgeCountByRelation(inVertID, outVertID, "Contained_Within");
			//edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "Contained_Within");
			assertTrue(edgeIDCount == 1);
			//edgeID = edgeIDList.get(0);	
			//edge = db.getEdgeByID(edgeID);
			//assertNotNull(edge);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
		
	@Test
	public void testLoadIndicatorDuplicateTest() {	
		System.out.println("[Running] alignment.alignment_v2.AlignTest.testLoadIndicatorDuplicateTest()");
		
		String graphSectionOne = 
			"{"+
			"  \"vertices\": {"+
			"    \"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\": {"+
			"      \"vertexType\": \"TTP\","+
			"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
			"      \"name\": \"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\""+
			"    },"+
			"    \"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\": {"+
			"      \"vertexType\": \"Course_Of_Action\","+
			"      \"sourceDocument\": \"<stix:Course_Of_Action xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"coa:CourseOfActionType\\\" id=\\\"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\\\"><coa:Title xmlns:coa=\\\"http://stix.mitre.org/CourseOfAction-1\\\">COA Title<\\/coa:Title><\\/stix:Course_Of_Action>\","+
			"      \"name\": \"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\""+
			"    },"+
			"    \"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\": {"+
			"      \"vertexType\": \"Indicator\","+
			"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\\\" /><\\/indicator:Indicated_TTP><indicator:Suggested_COAs xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><indicator:Suggested_COA><stixCommon:Course_Of_Action xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"coa:CourseOfActionType\\\" idref=\\\"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\\\" /><\\/indicator:Suggested_COA><\\/indicator:Suggested_COAs><\\/stix:Indicator>\","+
			"      \"name\": \"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\","+
			"		\"alias\": [" +
			"			\"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\"," +
			"			\"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\"]" +
			"    }"+
			"  },"+
			"  \"edges\": ["+
			"    {"+
			"      \"outVertID\": \"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\","+
			"      \"inVertID\": \"TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341\","+
			"      \"relation\": \"IndicatedTTP\""+
			"    },"+
			"    {"+
			"      \"outVertID\": \"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\","+
			"      \"inVertID\": \"Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb\","+
			"      \"relation\": \"SuggestedCOA\""+
			"    }"+
			"  ]"+
			"}";

		String graphSectionTwo = 
			"{"+
			"  \"vertices\": {"+
			"    \"Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402\": {"+
			"      \"vertexType\": \"Indicator\","+
			"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\\\" /><\\/indicator:Indicated_TTP><\\/stix:Indicator>\","+
			"      \"name\": \"Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402\","+
			"		\"alias\": [\"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\"]" +
			"    },"+
			"    \"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\": {"+
			"      \"vertexType\": \"TTP\","+
			"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
			"      \"name\": \"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\""+
			"    }"+
			"  },"+
			"  \"edges\": ["+
			"    {"+
			"      \"outVertID\": \"Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402\","+
			"      \"inVertID\": \"TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70\","+
			"      \"relation\": \"IndicatedTTP\""+
			"    }"+
			"  ]"+
			"}";

		try {
			Align align = new Align();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			DBConnectionJson db = align.getConnection();

			JSONObject graph = new JSONObject(graphSectionOne);
			jsonArrayToSetConverter(graph);
			align.load(graph);
			graph = new JSONObject(graphSectionOne);
			jsonArrayToSetConverter(graph);

			System.out.println("Testing TTP ...");
			JSONObject vert = db.getVertByName("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
			JSONObject originalVert = graph.getJSONObject("vertices").getJSONObject("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
			assertTrue(compareJSONObjects(vert, originalVert));
			
			System.out.println("Testing Course_Of_Action ...");
			vert = db.getVertByName("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
			originalVert = graph.getJSONObject("vertices").getJSONObject("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
			assertTrue(compareJSONObjects(vert, originalVert));

			System.out.println("Testing Indicator ...");
			vert = db.getVertByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
			originalVert = graph.getJSONObject("vertices").getJSONObject("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
			assertTrue(compareJSONObjects(vert, originalVert));
			
			String outVertID = null;
			String inVertID = null;
			List<String> edgeIDList = null;
			String edgeID = null;
			JSONObject edge = null;

			System.out.println("Testing Indicator -> IndicatedTTP -> TTP edge ...");
			inVertID = db.getVertIDByName("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
			outVertID = db.getVertIDByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
			int edgeIDCount = db.getEdgeCountByRelation(inVertID, outVertID, "IndicatedTTP");
			//edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "IndicatedTTP");
			assertTrue(edgeIDCount == 1);
			//edgeID = edgeIDList.get(0);	
			//edge = db.getEdgeByID(edgeID);
			//assertNotNull(edge);	
			
			System.out.println("Testing Indicator -> SuggestedCOA -> Course_Of_Action edge ...");
			inVertID = db.getVertIDByName("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
			outVertID = db.getVertIDByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
			edgeIDCount = db.getEdgeCountByRelation(inVertID, outVertID, "SuggestedCOA");
			//edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "SuggestedCOA");
			assertTrue(edgeIDCount == 1);
			//edgeID = edgeIDList.get(0);	
			//edge = db.getEdgeByID(edgeID);
			//assertNotNull(edge);
			
			graph = new JSONObject(graphSectionTwo);
			jsonArrayToSetConverter(graph);
			JSONObject vs = graph.getJSONObject("vertices");
			align.load(graph);
			System.out.println("Testing Indicator duplicate ...");
			vert = db.getVertByName("Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402");
			assertNull(vert);	
			
			System.out.println("Testing TTP duplicate ...");
			vert = db.getVertByName("TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70");
			assertNull(vert);	
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void testLoadNestedIndicatorsTest() {
		System.out.println("[Running] alignment.alignment_v2.AlignTest.testLoadNestedIndicatorsTest()");
		
			String graphSectionOne = 
				"{"+
				"  \"vertices\": {"+
				"    \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\\\" /><\\/indicator:Indicated_TTP><indicator:Suggested_COAs xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><indicator:Suggested_COA><stixCommon:Course_Of_Action xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"coa:CourseOfActionType\\\" idref=\\\"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\\\" /><\\/indicator:Suggested_COA><\\/indicator:Suggested_COAs><indicator:Related_Indicators xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><indicator:Related_Indicator><stixCommon:Indicator xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"indicator:IndicatorType\\\" idref=\\\"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\\\" /><\\/indicator:Related_Indicator><\\/indicator:Related_Indicators><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\""+
				"    },"+
				"    \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\""+
				"    },"+
				"    \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\": {"+
				"      \"vertexType\": \"Course_Of_Action\","+
				"      \"sourceDocument\": \"<stix:Course_Of_Action xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"coa:CourseOfActionType\\\" id=\\\"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\\\"><coa:Title xmlns:coa=\\\"http://stix.mitre.org/CourseOfAction-1\\\">COA Title<\\/coa:Title><\\/stix:Course_Of_Action>\","+
				"      \"name\": \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\""+
				"    },"+
				"    \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\\\" /><\\/indicator:Indicated_TTP><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\","+
				"		\"alias\": [" +
				"			\"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\"," +
				"			\"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\"," +
				"			\"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\","+
				"			\"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\"]" +
				"    },"+
				"    \"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\""+
				"    },"+
				"    \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\""+
				"    },"+
				"    \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\\\" /><\\/indicator:Indicated_TTP><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\""+
				"    }"+
				"  },"+
				"  \"edges\": ["+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\","+
				"      \"inVertID\": \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\","+
				"      \"inVertID\": \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\","+
				"      \"relation\": \"SuggestedCOA\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\","+
				"      \"inVertID\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\","+
				"      \"relation\": \"RelatedIndicator\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\","+
				"      \"inVertID\": \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\","+
				"      \"inVertID\": \"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    }"+
				"  ]"+
				"}";
			
			String graphSectionTwo = 
				"{"+
				"  \"vertices\": {"+
				"    \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc26\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc25\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\\\" /><\\/indicator:Indicated_TTP><indicator:Suggested_COAs xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><indicator:Suggested_COA><stixCommon:Course_Of_Action xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"coa:CourseOfActionType\\\" idref=\\\"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\\\" /><\\/indicator:Suggested_COA><\\/indicator:Suggested_COAs><indicator:Related_Indicators xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><indicator:Related_Indicator><stixCommon:Indicator xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"indicator:IndicatorType\\\" idref=\\\"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\\\" /><\\/indicator:Related_Indicator><\\/indicator:Related_Indicators><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc26\""+
				"    },"+
				"    \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cc\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cb\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cc\""+
				"    },"+
				"    \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c5\": {"+
				"      \"vertexType\": \"Course_Of_Action\","+
				"      \"sourceDocument\": \"<stix:Course_Of_Action xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"coa:CourseOfActionType\\\" id=\\\"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c4\\\"><coa:Title xmlns:coa=\\\"http://stix.mitre.org/CourseOfAction-1\\\">COA Title<\\/coa:Title><\\/stix:Course_Of_Action>\","+
				"      \"name\": \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c5\""+
				"    },"+
				"    \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025c\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\\\" /><\\/indicator:Indicated_TTP><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025c\""+
				"    },"+
				"    \"TTP-512ead41-e81e-468c-a3c0-09c3218aede8\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-512ead41-e81e-468c-a3c0-09c3218aede8\""+
				"    },"+
				"    \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b7\": {"+
				"      \"vertexType\": \"TTP\","+
				"      \"sourceDocument\": \"<stix:TTP xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ttp:TTPType\\\" id=\\\"TTP-787e5622-4f09-4f41-b8f3-19b8535889b6\\\"><ttp:Title xmlns:ttp=\\\"http://stix.mitre.org/TTP-1\\\">Related TTP<\\/ttp:Title><\\/stix:TTP>\","+
				"      \"name\": \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b7\""+
				"    },"+
				"    \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7b\": {"+
				"      \"vertexType\": \"Indicator\","+
				"      \"sourceDocument\": \"<stix:Indicator xmlns:stix=\\\"http://stix.mitre.org/stix-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"indicator:IndicatorType\\\" id=\\\"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7a\\\"><indicator:Title xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\">Indicator One Title<\\/indicator:Title><indicator:Indicated_TTP xmlns:indicator=\\\"http://stix.mitre.org/Indicator-2\\\"><stixCommon:TTP xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xsi:type=\\\"ttp:TTPType\\\" idref=\\\"TTP-512ead41-e81e-468c-a3c0-09c3218aede7\\\" /><\\/indicator:Indicated_TTP><\\/stix:Indicator>\","+
				"      \"name\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7b\""+
				"    }"+
				"  },"+
				"  \"edges\": ["+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc26\","+
				"      \"inVertID\": \"TTP-2aea7e21-46a9-4e52-9338-6196fc33c3cc\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc26\","+
				"      \"inVertID\": \"Course_Of_Action-b3d87523-0107-44a8-a3fc-bdda0c28c8c5\","+
				"      \"relation\": \"SuggestedCOA\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-d68b90a2-09c3-4cac-9e78-03a490b1dc26\","+
				"      \"inVertID\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7b\","+
				"      \"relation\": \"RelatedIndicator\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025c\","+
				"      \"inVertID\": \"TTP-787e5622-4f09-4f41-b8f3-19b8535889b7\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    },"+
				"    {"+
				"      \"outVertID\": \"Indicator-5cce612d-29d4-438c-980c-82d7f66bdb7b\","+
				"      \"inVertID\": \"TTP-512ead41-e81e-468c-a3c0-09c3218aede8\","+
				"      \"relation\": \"IndicatedTTP\""+
				"    }"+
				"  ]"+
				"}";

		try {
			Align align = new Align();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			DBConnectionJson db = align.getConnection();
			JSONObject graph = new JSONObject(graphSectionOne);
			jsonArrayToSetConverter(graph);
			align.load(graph);
			graph = new JSONObject(graphSectionTwo);
			jsonArrayToSetConverter(graph);
			align.load(graph);
			List<DBConstraint> constraints1 = new ArrayList<DBConstraint>();
			constraints1.add(db.getConstraint("vertexType", Condition.eq, "Indicator"));
			List<String> indicatorList = db.getVertIDsByConstraints(constraints1);
			assertTrue(indicatorList.size() == 1);

			List<DBConstraint> constraints2 = new ArrayList<DBConstraint>();
			constraints2.add(db.getConstraint("vertexType", Condition.eq, "TTP"));
			List<String> ttpList = db.getVertIDsByConstraints(constraints2);
			assertTrue(ttpList.size() == 1);

			List<DBConstraint> constraints3 = new ArrayList<DBConstraint>();
			constraints3.add(db.getConstraint("vertexType", Condition.eq, "Course_Of_Action"));
			List<String> coaList = db.getVertIDsByConstraints(constraints3);
			assertTrue(coaList.size() == 1);
			List<String> indicatedTTP = db.getInVertIDsByRelation(indicatorList.get(0), "IndicatedTTP");
			assertTrue(indicatedTTP.size() == 1);
			List<String> suggestedCOA = db.getInVertIDsByRelation(indicatorList.get(0), "SuggestedCOA");
			assertTrue(suggestedCOA.size() == 1);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
