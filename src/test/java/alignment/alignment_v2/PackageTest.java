package alignment.alignment_v2;

import alignment.alignment_v2.PreprocessSTIX;
import alignment.alignment_v2.GraphConstructor;
import alignment.alignment_v2.Align;

import static org.junit.Assert.*;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import org.json.JSONObject;
import org.json.JSONArray;

import org.junit.Test;

import javax.xml.namespace.QName;					

import org.xml.sax.SAXException; 

import org.jdom2.Element;
import org.jdom2.output.XMLOutputter;

import java.io.IOException;

import org.mitre.stix.stix_1.*;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.cybox_2.Observables;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.indicator_2.Indicator; 
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.campaign_1.Campaign;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.common_1.ExploitTargetsType;
import org.mitre.stix.incident_1.Incident;
import org.mitre.stix.threatactor_1.ThreatActor;
import org.mitre.stix.common_1.TTPBaseType;
import org.mitre.stix.common_1.CampaignBaseType;

import java.nio.file.Files;
import java.nio.file.Paths;

public class PackageTest {
	
	/**
	 * Tests normalize stix: Incident with Indicator, Observable, TTP, and ExploitTarget
	 */
	@Test
	public void test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
		try {
			String stix =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:STIX_Source-f0ce33ae-7524-45bb-b397-4a1585ee2cc7\" " +
				"    timestamp=\"2015-10-15T20:11:17.124Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:incident=\"http://stix.mitre.org/Incident-1\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:stucco=\"gov.ornl.stucco\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>STIX Source</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:Observable-6700\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Incidents> " +
				"        <stix:Incident  id=\"stucco:Incident-6400\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"incident:IncidentType\"> " +
				"            <incident:Description>Some incident description</incident:Description> " +
				"            <incident:Related_Indicators> " +
				"                <incident:Related_Indicator> " +
				"                    <stixCommon:Indicator id=\"stucco:Indicator-12345\" xsi:type=\"indicator:IndicatorType\"> " +
				"                        <indicator:Description>Some description of Related Indicator</indicator:Description> " +
				"                        <indicator:Observable id=\"stucco:Observable-6789\"> " +
				"                            <cybox:Title>Observable - Title</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Source</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                        </indicator:Observable> " +
				"                        <indicator:Indicated_TTP> " +
				"                            <stixCommon:TTP id=\"stucco:TTP-12345\" xsi:type=\"ttp:TTPType\"> " +
				"                                <ttp:Description>TTP - Description</ttp:Description> " +
				"                                <ttp:Behavior> " +
				"                                    <ttp:Malware> " +
				"                                    <ttp:Malware_Instance> " +
				"                                    <ttp:Type>Malware - Type</ttp:Type> " +
				"                                    <ttp:Name>Malware - Name</ttp:Name> " +
				"                                    </ttp:Malware_Instance> " +
				"                                    </ttp:Malware> " +
				"                                </ttp:Behavior> " +
				"                                <ttp:Exploit_Targets> " +
				"                                    <ttp:Exploit_Target> " +
				"                                    <stixCommon:Exploit_Target " +
				"                                    id=\"stucco:ExploitTarget-12345\" xsi:type=\"et:ExploitTargetType\"> " +
				"                                    <et:Title>ExploitTarget - Title</et:Title> " +
				"                                    </stixCommon:Exploit_Target> " +
				"                                    </ttp:Exploit_Target> " +
				"                                </ttp:Exploit_Targets> " +
				"                            </stixCommon:TTP> " +
				"                        </indicator:Indicated_TTP> " +
				"                    </stixCommon:Indicator> " +
				"                </incident:Related_Indicator> " +
				"            </incident:Related_Indicators> " +
				"        </stix:Incident> " +
				"    </stix:Incidents> " +
				"</stix:STIX_Package> ";

			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			GraphConstructor graphConstructor = new GraphConstructor();
			Align align = new Align();
			align.setSearchForDuplicates(true);
			align.setAlignVertProps(true);
			InMemoryDBConnectionJson db = align.getConnection();

			STIXPackage pack = new STIXPackage().fromXMLString(stix);
			assertTrue(preprocessSTIX.validate(pack));

			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			boolean loaded = align.load(graph);

			assertTrue(db.getVertCount() == 5);
			assertTrue(db.getEdgeCount() == 4);

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/**
	 * Tests normalize stix: ~20MB malwaredomainlist_hostlist
	 */
//	@Test
	public void test_normalizeSTIX_malwaredomainlist_hostlist() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_malwaredomainlist_hostlist()");
		try {
			String stix = new String(Files.readAllBytes(Paths.get("resources/testData/malwaredomainlist_hostlist.xml")));
		//	String malwaredomainlist_hostlist = new String(Files.readAllBytes(Paths.get("resources/testData/abuse_ch.xml")));
		
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			GraphConstructor graphConstructor = new GraphConstructor();
			Align align = new Align();
			InMemoryDBConnectionJson db = align.getConnection();

			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(stix);
			System.out.println("Done preprocessSTIX");
			JSONObject graph = graphConstructor.constructGraph(stixElements);
			System.out.println("Done graphConstructor");
			boolean loaded = align.load(graph);

			System.out.println(db.getVertCount());
			System.out.println(db.getEdgeCount());
			db.saveVertices("resources/testData/vertices.json");
			db.saveEdges("resources/testData/edges.json");

			assertTrue(true);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}



