package alignment.alignment_v2;

import static org.junit.Assert.*;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import org.junit.Test;

import javax.xml.namespace.QName;					
 
import org.xml.sax.SAXException; 

import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute; 
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
import org.mitre.stix.common_1.IndicatorBaseType;

public class PreprocessSTIXTest extends PreprocessSTIX {
	
	/*
	 * Tests normalize stix: Incident with Indicator, Observable, TTP, and ExploitTarget
	 */
	@Test
	public void test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
		try {
			String testStixString =
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

			String expectedStixString = 
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
				"        <cybox:Observable id=\"stucco:Observable-6789\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Source</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:Observable-6700\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator id=\"stucco:Indicator-12345\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Description>Some description of Related Indicator</indicator:Description> " +
				"            <indicator:Observable idref=\"stucco:Observable-6789\"/> " +
				"            <indicator:Indicated_TTP> " +
				"                <stixCommon:TTP idref=\"stucco:TTP-12345\" xsi:type=\"ttp:TTPType\"/> " +
				"            </indicator:Indicated_TTP> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"    <stix:TTPs> " +
				"	<stix:TTP id=\"stucco:TTP-12345\" " +
        "	     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Description>TTP - Description</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Malware> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type</ttp:Type> " +
				"                        <ttp:Name>Malware - Name</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                </ttp:Malware> " +
				"            </ttp:Behavior> " +
				"            <ttp:Exploit_Targets> " +
				"                <ttp:Exploit_Target> " +
				"                    <stixCommon:Exploit_Target " +
				"                        idref=\"stucco:ExploitTarget-12345\" xsi:type=\"et:ExploitTargetType\"/> " +
				"                </ttp:Exploit_Target> " +
				"            </ttp:Exploit_Targets> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target id=\"stucco:ExploitTarget-12345\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>ExploitTarget - Title</et:Title> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"    <stix:Incidents> " +
				"        <stix:Incident id=\"stucco:Incident-6400\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"incident:IncidentType\"> " +
				"            <incident:Description>Some incident description</incident:Description> " +
				"            <incident:Related_Indicators> " +
				"                <incident:Related_Indicator> " +
				"                    <stixCommon:Indicator idref=\"stucco:Indicator-12345\" xsi:type=\"indicator:IndicatorType\"/> " +
				"                </incident:Related_Indicator> " +
				"            </incident:Related_Indicators> " +
				"        </stix:Incident> " +
				"    </stix:Incidents> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);

			System.out.println("Testing Indicator ...");
			Indicator expectedIndicator = (Indicator) expectedElements.getIndicators().getIndicators().get(0);
			QName qname = expectedIndicator.getId();
			String id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element indicator = stixElements.get(id);
			String normalizedIndicatorString = new XMLOutputter().outputString(indicator);
			Indicator normalizedIndicator = new Indicator().fromXMLString(normalizedIndicatorString);
			assertTrue(normalizedIndicator.validate());
			assertTrue(expectedIndicator.equals(normalizedIndicator));

			System.out.println("Testing TTP ...");
			TTP expectedTtp = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			qname = expectedTtp.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element ttp = stixElements.get(id);
			String normalizedTTPString = new XMLOutputter().outputString(ttp);
			TTP normalizedTtp = new TTP().fromXMLString(normalizedTTPString);
			assertTrue(normalizedTtp.validate());
			assertTrue(expectedTtp.equals(normalizedTtp));

			System.out.println("Testing Incident ...");
			Incident expectedIncident = (Incident) expectedElements.getIncidents().getIncidents().get(0);
			qname = expectedIncident.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element incident = stixElements.get(id);
			String normalizedIncidentString = new XMLOutputter().outputString(incident);
			Incident normalizedIncident = new Incident().fromXMLString(normalizedIncidentString);
			assertTrue(normalizedIncident.validate());
			assertTrue(expectedIncident.equals(normalizedIncident));

			System.out.println("Testing Observable ...");
			Observable expectedObservable = expectedElements.getObservables().getObservables().get(0);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element observable = stixElements.get(id);
			String normalizedObservableString = new XMLOutputter().outputString(observable);
			Observable normalizedObservable = new Observable().fromXMLString(normalizedObservableString);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));			

			System.out.println("Testing Observable ...");
			expectedObservable = expectedElements.getObservables().getObservables().get(1);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			observable = stixElements.get(id);
			normalizedObservableString = new XMLOutputter().outputString(observable);
			normalizedObservable = new Observable().fromXMLString(normalizedObservableString);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));	

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: ExploitTarget, Observables, and CourseOfAction
	 */
	@Test
	public void test_normalizeSTIX_ExploitTarget_Observables_COA() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_ExploitTarget_Observables_COA()");
		try {
		
			String testStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Bugtraq-6b79a9f7-b391-4384-9b5d-831ec9572e4e\" " +
				"    timestamp=\"2015-10-19T14:47:07.773Z\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Bugtraq</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:Bugtraq-90dcf3c4-746f-4207-b990-a69b5131cf6e\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability.</et:Description> " +
				"                <et:Short_Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability</et:Short_Description> " +
				"                <et:OSVDB_ID>2222</et:OSVDB_ID> " +
				"                <et:Source>Bugtraq</et:Source> " +
				"                <et:Published_DateTime>2001-01-16T00:00:00.000-05:00</et:Published_DateTime> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable id=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"> " +
				"                            <cybox:Title>Software</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.28\"> " +
				"                                <cybox:Description>SSH Communications Security SSH 1.2.28</cybox:Description> " +
				"                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                                    <ProductObj:Product>SSH Communications Security SSH 1.2.28</ProductObj:Product> " +
				"                                </cybox:Properties> " +
				"                            </cybox:Object> " +
				"                        </stixCommon:Observable> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable id=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"> " +
				"                            <cybox:Title>Software</cybox:Title> " +
				"                            <cybox:Observable_Source> " +
				"                                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"                            </cybox:Observable_Source> " +
				"                            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.27\"> " +
				"                                <cybox:Description>SSH Communications Security SSH 1.2.27</cybox:Description> " +
				"                                <cybox:Properties xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                                    <ProductObj:Product>SSH Communications Security SSH 1.2.27</ProductObj:Product> " +
				"                                </cybox:Properties> " +
				"                            </cybox:Object> " +
				"                        </stixCommon:Observable> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"            <et:Potential_COAs> " +
				"                <et:Potential_COA> " +
				"                    <stixCommon:Course_Of_Action " +
				"                        id=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" xsi:type=\"coa:CourseOfActionType\"> " +
				"                        <coa:Title>Vulnerability</coa:Title> " +
				"                        <coa:Description>Solution: Patches available: SSH Communications Security SSH 1.2.27</coa:Description> " +
				"                        <coa:Information_Source> " +
				"                            <stixCommon:Identity> " +
				"                                <stixCommon:Name>Bugtraq</stixCommon:Name> " +
				"                            </stixCommon:Identity> " +
				"                        </coa:Information_Source> " +
				"                    </stixCommon:Course_Of_Action> " +
				"                </et:Potential_COA> " +
				"            </et:Potential_COAs> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";
			
			String expectedStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    id=\"stucco:Bugtraq-6b79a9f7-b391-4384-9b5d-831ec9572e4e\" " +
				"    timestamp=\"2015-10-19T14:47:07.773Z\" " +
				"    xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:ProductObj=\"http://cybox.mitre.org/objects#ProductObject-2\" " +
				"    xmlns:coa=\"http://stix.mitre.org/CourseOfAction-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Title>Bugtraq</stix:Title> " +
				"    </stix:STIX_Header> " +
				"    <stix:Observables cybox_major_version=\"2.0\" cybox_minor_version=\"1.0\"> " +
				"        <cybox:Observable id=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.28\"> " +
				"                <cybox:Description>SSH Communications Security SSH 1.2.28</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>SSH Communications Security SSH 1.2.28</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"> " +
				"            <cybox:Title>Software</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Bugtraq</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
				"            <cybox:Object id=\"stucco:software-SSH_Communications_Security_SSH_1.2.27\"> " +
				"                <cybox:Description>SSH Communications Security SSH 1.2.27</cybox:Description> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProductObj:ProductObjectType\"> " +
				"                    <ProductObj:Product>SSH Communications Security SSH 1.2.27</ProductObj:Product> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:Bugtraq-90dcf3c4-746f-4207-b990-a69b5131cf6e\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Title>Vulnerability</et:Title> " +
				"            <et:Vulnerability> " +
				"                <et:Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability.</et:Description> " +
				"                <et:Short_Description>SSH Secure-RPC Weak Encrypted Authentication Vulnerability</et:Short_Description> " +
				"                <et:OSVDB_ID>2222</et:OSVDB_ID> " +
				"                <et:Source>Bugtraq</et:Source> " +
				"                <et:Published_DateTime>2001-01-16T00:00:00.000-05:00</et:Published_DateTime> " +
				"                <et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-5a4b8795-a590-4573-a666-2e225f361a50\"/> " +
				"                    </et:Affected_Software> " +
				"                    <et:Affected_Software> " +
				"                        <stixCommon:Observable idref=\"stucco:software-de0b12aa-07ed-4e35-9a84-a94124476780\"/> " +
				"                    </et:Affected_Software> " +
				"                </et:Affected_Software> " +
				"            </et:Vulnerability> " +
				"            <et:Potential_COAs> " +
				"                <et:Potential_COA> " +
				"                    <stixCommon:Course_Of_Action " +
				"                        idref=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" xsi:type=\"coa:CourseOfActionType\"/> " +
				"                </et:Potential_COA> " +
				"            </et:Potential_COAs> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"    <stix:Courses_Of_Action> " +
				"        <stix:Course_Of_Action " +
				"            id=\"stucco:Vulnerability-e2ebb9da-6332-4793-95c9-0668804b01b8\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"coa:CourseOfActionType\"> " +
				"            <coa:Title>Vulnerability</coa:Title> " +
				"            <coa:Description>Solution: Patches available: SSH Communications Security SSH 1.2.27</coa:Description> " +
				"            <coa:Information_Source> " +
				"                <stixCommon:Identity> " +
				"                    <stixCommon:Name>Bugtraq</stixCommon:Name> " +
				"                </stixCommon:Identity> " +
				"            </coa:Information_Source> " +
				"        </stix:Course_Of_Action> " +
				"    </stix:Courses_Of_Action> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);

			System.out.println("Testing ExploitTarget ...");
			ExploitTarget expectedEt = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(0);
			QName qname = expectedEt.getId();
			String id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element et = stixElements.get(id);
			String normalizedEtString = new XMLOutputter().outputString(et);
			ExploitTarget normalizedEt = new ExploitTarget().fromXMLString(normalizedEtString);
			assertTrue(normalizedEt.validate());
			assertTrue(expectedEt.equals(normalizedEt));

			System.out.println("Testing Observable ...");
			Observable expectedObservable = expectedElements.getObservables().getObservables().get(0);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element observable = stixElements.get(id);
			String normalizedObservableString = new XMLOutputter().outputString(observable);
			Observable normalizedObservable = new Observable().fromXMLString(normalizedObservableString);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));			

			System.out.println("Testing Observable ...");
			expectedObservable = expectedElements.getObservables().getObservables().get(1);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			observable = stixElements.get(id);
			normalizedObservableString = new XMLOutputter().outputString(observable);
			normalizedObservable = new Observable().fromXMLString(normalizedObservableString);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));	

			System.out.println("Testing CourseOfAction ...");
			CourseOfAction expectedCoa = (CourseOfAction) expectedElements.getCoursesOfAction().getCourseOfActions().get(0);
			qname = expectedCoa.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(stixElements.containsKey(id));
			Element coa = stixElements.get(id);
			String normalizedCoaString = new XMLOutputter().outputString(coa);
			CourseOfAction normalizedCoa = new CourseOfAction().fromXMLString(normalizedCoaString);
			assertTrue(normalizedCoa.validate());
			assertTrue(expectedCoa.equals(normalizedCoa));		

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: nested Indicators and nested Observables
	 */
	@Test
	public void test_normalizeSTIX_Indicator_Observable() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Indicator_Observable()");
		try {
			String testStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:UnixProcessObj=\"http://cybox.mitre.org/objects#UnixProcessObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\"> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            id=\"stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Indicator</indicator:Title> " +
				"            <indicator:Related_Indicators> " +
				"                <indicator:Related_Indicator> " +
				"                    <stixCommon:Relationship>Some Relationship</stixCommon:Relationship> " +
				"                    <stixCommon:Indicator " +
				"                        id=\"stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225\" xsi:type=\"indicator:IndicatorType\"> " +
				"                        <indicator:Title>Inner Indicator</indicator:Title> " +
				"                        <indicator:Observable id=\"stucco:Observable-67029ece-7402-46ba-83fa-ba27e81dc7c7\"> " +
				"                            <cybox:Title>Service Observable</cybox:Title> " +
				"                            <cybox:Object> " +
				"                                <cybox:Properties xsi:type=\"UnixProcessObj:UnixProcessObjectType\"> " +
				"                                    <ProcessObj:PID>pid</ProcessObj:PID> " +
				"                                    <ProcessObj:Name>Unix Process Name</ProcessObj:Name> " +
				"                                    <ProcessObj:Port_List> " +
				"                                    <ProcessObj:Port> " +
				"                                    <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                                    </ProcessObj:Port> " +
				"                                    </ProcessObj:Port_List> " +
				"                                    <UnixProcessObj:Session_ID>123</UnixProcessObj:Session_ID> " +
				"                                </cybox:Properties> " +
				"                            </cybox:Object> " +
				"                        </indicator:Observable> " +
				"                    </stixCommon:Indicator> " +
				"                </indicator:Related_Indicator> " +
				"            </indicator:Related_Indicators> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";

			String expectedStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package xmlns=\"http://xml/metadataSharing.xsd\" " +
				"    xmlns:PortObj=\"http://cybox.mitre.org/objects#PortObject-2\" " +
				"    xmlns:ProcessObj=\"http://cybox.mitre.org/objects#ProcessObject-2\" " +
				"    xmlns:UnixProcessObj=\"http://cybox.mitre.org/objects#UnixProcessObject-2\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\"> " +
				"    <stix:Observables cybox_major_version=\"1.0\" cybox_minor_version=\"2.0\"> " +
				"        <cybox:Observable " +
				"            id=\"stucco:Observable-67029ece-7402-46ba-83fa-ba27e81dc7c7\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"            <cybox:Title>Service Observable</cybox:Title> " +
				"            <cybox:Object> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"UnixProcessObj:UnixProcessObjectType\"> " +
				"                    <ProcessObj:PID>pid</ProcessObj:PID> " +
				"                    <ProcessObj:Name>Process Name</ProcessObj:Name> " +
				"                    <ProcessObj:Port_List> " +
				"                        <ProcessObj:Port> " +
				"                            <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                        </ProcessObj:Port> " +
				"                    </ProcessObj:Port_List> " +
				"                    <UnixProcessObj:Session_ID>123</UnixProcessObj:Session_ID> " +
				"                </cybox:Properties> " +
				"                <cybox:Related_Objects> " +
				"                    <cybox:Related_Object idref=\"stucco:Observable-4b786f4b-807a-427a-abf2-64b4f825121b\"/> " +
				"                </cybox:Related_Objects> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable " +
				"            id=\"stucco:Observable-4b786f4b-807a-427a-abf2-64b4f825121b\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"            <cybox:Object> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ProcessObj:ProcessObjectType\"> " +
				"                    <ProcessObj:PID>pid</ProcessObj:PID> " +
				"                    <ProcessObj:Name>Process name</ProcessObj:Name> " +
				"                    <ProcessObj:Port_List> " +
				"                        <ProcessObj:Port object_reference=\"stucco:Observable-443412ee-a026-47f1-9227-24397986c4d8\"/> " +
				"                    </ProcessObj:Port_List> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable " +
				"            id=\"stucco:Observable-443412ee-a026-47f1-9227-24397986c4d8\" xmlns:stucco=\"gov.ornl.stucco\"> " +
				"            <cybox:Object> " +
				"                <cybox:Properties " +
				"                    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"PortObj:PortObjectType\"> " +
				"                    <PortObj:Port_Value>80</PortObj:Port_Value> " +
				"                </cybox:Properties> " +
				"            </cybox:Object> " +
				"        </cybox:Observable> " +
				"    </stix:Observables> " +
				"    <stix:Indicators> " +
				"        <stix:Indicator " +
				"            id=\"stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Indicator</indicator:Title> " +
				"            <indicator:Related_Indicators> " +
				"                <indicator:Related_Indicator> " +
				"                    <stixCommon:Relationship>Some Relationship</stixCommon:Relationship> " +
				"                    <stixCommon:Indicator " +
				"                        idref=\"stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225\" xsi:type=\"indicator:IndicatorType\"/> " +
				"                </indicator:Related_Indicator> " +
				"            </indicator:Related_Indicators> " +
				"        </stix:Indicator> " +
				"        <stix:Indicator " +
				"            id=\"stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"indicator:IndicatorType\"> " +
				"            <indicator:Title>Inner Indicator</indicator:Title> " +
				"            <indicator:Observable idref=\"stucco:Observable-67029ece-7402-46ba-83fa-ba27e81dc7c7\"/> " +
				"        </stix:Indicator> " +
				"    </stix:Indicators> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);
			List<IndicatorBaseType> indicators = expectedElements.getIndicators().getIndicators();
			String outerIndicatorId = "Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a";
			QName id = indicators.get(0).getId();
			Indicator outerIndicator = null;
			Indicator innerIndicator = null;
			if (outerIndicatorId.equals(id.getLocalPart())) {
				outerIndicator = (Indicator) indicators.get(0);
				innerIndicator = (Indicator) indicators.get(1);
			} else {
				outerIndicator = (Indicator) indicators.get(1);
				innerIndicator = (Indicator) indicators.get(0);
			}

			System.out.println("Testing Indicator ... ");
			Element normalizedElement = stixElements.get("stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a");
			Indicator normalizedIndicator = new Indicator().fromXMLString(new XMLOutputter().outputString(normalizedElement));
			assertTrue(normalizedIndicator.validate());
			assertTrue(outerIndicator.equals(normalizedIndicator));
			stixElements.remove("stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a");

			System.out.println("Testing Indicator ... ");
			normalizedElement = stixElements.get("stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225");
			normalizedIndicator = new Indicator().fromXMLString(new XMLOutputter().outputString(normalizedElement));
			assertTrue(normalizedIndicator.validate());
			assertTrue(innerIndicator.equals(normalizedIndicator));
			stixElements.remove("stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225");

			System.out.println("Testing Unix Account ... ");
			normalizedElement = stixElements.get("stucco:Observable-67029ece-7402-46ba-83fa-ba27e81dc7c7");
			Element object = normalizedElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element properties = object.getChild("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element pid = properties.getChild("PID", Namespace.getNamespace("ProcessObj","http://cybox.mitre.org/objects#ProcessObject-2"));
			assertEquals(pid.getText(), "pid");
			Element name = properties.getChild("Name", Namespace.getNamespace("ProcessObj","http://cybox.mitre.org/objects#ProcessObject-2"));
			assertEquals(name.getText(), "Unix Process Name");
			Element portList = properties.getChild("Port_List", Namespace.getNamespace("ProcessObj", "http://cybox.mitre.org/objects#ProcessObject-2"));
			Element port = portList.getChild("Port", Namespace.getNamespace("ProcessObj", "http://cybox.mitre.org/objects#ProcessObject-2"));
			String portIdref = port.getAttributeValue("object_reference");
			assertTrue(stixElements.containsKey(portIdref));
			Element sessionId = properties.getChild("Session_ID", Namespace.getNamespace("UnixProcessObj", "http://cybox.mitre.org/objects#UnixProcessObject-2"));
			assertEquals(sessionId.getText(), "123");

			System.out.println("Testing Port ... ");
			normalizedElement = stixElements.get(portIdref);
			object = normalizedElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			port = properties.getChild("Port_Value", Namespace.getNamespace("PortObj", "http://cybox.mitre.org/objects#PortObject-2"));
			String portValue = port.getText();
			assertEquals(portValue, "80");

		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: TTP with multiple Malware and Exploits
	 */
	@Test
	public void test_normalizeSTIX_TTP_Malware() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_TTP()");
		try {
			String testStixString =
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
				"    <stix:TTPs> " +
				" 	   <stix:TTP id=\"stucco:TTP-12345\" " +
	      		"		     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Description>TTP - Description</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Malware> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type 1</ttp:Type> " +
				"                        <ttp:Name>Malware - Name 1</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type 2</ttp:Type> " +
				"                        <ttp:Name>Malware - Name 2</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                </ttp:Malware> " +
				"            </ttp:Behavior> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"</stix:STIX_Package> ";

			String expectedStixString = 
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
				"    <stix:TTPs> " +
				"				<stix:TTP id=\"stucco:TTP-12345\" " +
        		"	     	xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Description>TTP - Description</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Malware> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type 1</ttp:Type> " +
				"                        <ttp:Name>Malware - Name 1</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                </ttp:Malware> " +
				"            </ttp:Behavior> " +
				"      </stix:TTP> " +
				"      <stix:TTP id=\"stucco:TTP-678910\" " +
        		"	     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Description>TTP - Description</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Malware> " +
				"                    <ttp:Malware_Instance> " +
				"                        <ttp:Type>Malware - Type 2</ttp:Type> " +
				"                        <ttp:Name>Malware - Name 2</ttp:Name> " +
				"                    </ttp:Malware_Instance> " +
				"                </ttp:Malware> " +
				"            </ttp:Behavior> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);
			TTP oldTTP = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			TTP newTTP = (TTP) expectedElements.getTTPs().getTTPS().get(1);
			if (!oldTTP.getId().getLocalPart().equals("TTP-12345")) {
				oldTTP = (TTP) expectedElements.getTTPs().getTTPS().get(1);
				newTTP = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			}

			System.out.println("Testing TTP ...");
			Element normalizedTTP = stixElements.get("stucco:TTP-12345");
			String normalizedTTPString = new XMLOutputter().outputString(normalizedTTP);
			TTP normalizedTtp = new TTP().fromXMLString(normalizedTTPString);
			normalizedTtp.setRelatedTTPs(null);
			assertTrue(normalizedTtp.validate());
			assertTrue(oldTTP.equals(normalizedTtp));
			stixElements.remove("stucco:TTP-12345");

			System.out.println("Testing TTP ...");
			for (String id : stixElements.keySet()) {
				normalizedTTP = stixElements.get(id);
			}
			normalizedTTPString = new XMLOutputter().outputString(normalizedTTP);
			normalizedTtp = new TTP().fromXMLString(normalizedTTPString);
			assertTrue(normalizedTtp.validate());
			normalizedTtp.setId(null);
			newTTP.setId(null);
			assertTrue(newTTP.equals(normalizedTtp));

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: TTP with multiple Exploits
	 */
	@Test
	public void test_normalizeSTIX_TTP_Exploits() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_TTP()");
		try {
			String testStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:TTPs> " +
				"        <stix:TTP id=\"stucco:TTP-da0a3940-4fb7-4e59-873e-4ab57fdc4d21\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Title>TTP Title</ttp:Title> " +
				"            <ttp:Description>TTP Description 1</ttp:Description> " +
				"            <ttp:Description>TTP Description 2</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Exploits> " +
				"                    <ttp:Exploit> " +
				"                        <ttp:Title>Exploit Title 1</ttp:Title> " +
				"                        <ttp:Description>Exploit Description 1</ttp:Description> " +
				"                    </ttp:Exploit> " +
				"                    <ttp:Exploit> " +
				"                        <ttp:Title>Exploit Title 2</ttp:Title> " +
				"                        <ttp:Description>Exploit Description 2</ttp:Description> " +
				"                    </ttp:Exploit> " +
				"                </ttp:Exploits> " +
				"            </ttp:Behavior> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"</stix:STIX_Package> ";

			String expectedStixString = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:ttp=\"http://stix.mitre.org/TTP-1\"> " +
				"    <stix:TTPs> " +
				"        <stix:TTP id=\"stucco:TTP-da0a3940-4fb7-4e59-873e-4ab57fdc4d21\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Title>TTP Title</ttp:Title> " +
				"            <ttp:Description>TTP Description 1</ttp:Description> " +
				"            <ttp:Description>TTP Description 2</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Exploits> " +
				"                    <ttp:Exploit> " +
				"                        <ttp:Title>Exploit Title 1</ttp:Title> " +
				"                        <ttp:Description>Exploit Description 1</ttp:Description> " +
				"                    </ttp:Exploit> " +
				"                </ttp:Exploits> " +
				"            </ttp:Behavior> " +
				"        </stix:TTP> " +
				"        <stix:TTP id=\"stucco:TTP-adf9ba1f-0a6b-4fef-9db2-cb07a74fd6bb\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"ttp:TTPType\"> " +
				"            <ttp:Title>TTP Title</ttp:Title> " +
				"            <ttp:Description>TTP Description 1</ttp:Description> " +
				"            <ttp:Description>TTP Description 2</ttp:Description> " +
				"            <ttp:Behavior> " +
				"                <ttp:Exploits> " +
				"                    <ttp:Exploit> " +
				"                        <ttp:Title>Exploit Title 2</ttp:Title> " +
				"                        <ttp:Description>Exploit Description 2</ttp:Description> " +
				"                    </ttp:Exploit> " +
				"                </ttp:Exploits> " +
				"            </ttp:Behavior> " +
				"        </stix:TTP> " +
				"    </stix:TTPs> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);
			TTP oldTTP = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			TTP newTTP = (TTP) expectedElements.getTTPs().getTTPS().get(1);
			String id = oldTTP.getId().getLocalPart();
			if (!id.equals("TTP-da0a3940-4fb7-4e59-873e-4ab57fdc4d21")) {
				oldTTP = (TTP) expectedElements.getTTPs().getTTPS().get(1);
				newTTP = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			}

			System.out.println("Testing TTP ...");
			Element normalizedTTP = stixElements.get("stucco:TTP-da0a3940-4fb7-4e59-873e-4ab57fdc4d21");
			String normalizedTTPString = new XMLOutputter().outputString(normalizedTTP);
			TTP normalizedTtp = new TTP().fromXMLString(normalizedTTPString);
			assertTrue(normalizedTtp.validate());
			normalizedTtp.setRelatedTTPs(null);
			assertTrue(oldTTP.equals(normalizedTtp));

			System.out.println("Testing TTP ...");
			stixElements.remove("stucco:TTP-da0a3940-4fb7-4e59-873e-4ab57fdc4d21");
			for (String key : stixElements.keySet()) {
				normalizedTTP = stixElements.get(key);
			}
			normalizedTTPString = new XMLOutputter().outputString(normalizedTTP);
			normalizedTtp = new TTP().fromXMLString(normalizedTTPString);
			normalizedTtp.setId(null);
			newTTP.setId(null);
			assertTrue(normalizedTtp.validate());
			assertTrue(newTTP.equals(normalizedTtp));

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: Exploit Target with multiple Vulnerabilities
	 */
	@Test
	public void test_normalizeSTIX_ExploitTarget_Vulnerability() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_ExploitTarget_Vulnerability()");
		try {
			String testStixString =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\"> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:ExploitTarget-71c0bdac-4a55-4143-87e8-afee94aa2460\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Vulnerability> " +
				"                <et:Title>Title 1</et:Title> " +
				"                <et:Description>Description 1</et:Description> " +
				"            </et:Vulnerability> " +
				"            <et:Vulnerability> " +
				"                <et:Title>Title 2</et:Title> " +
				"                <et:Description>Description 2</et:Description> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";

			String expectedStixString = 
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
				"<stix:STIX_Package xmlns:et=\"http://stix.mitre.org/ExploitTarget-1\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" xmlns:stixCommon=\"http://stix.mitre.org/common-1\"> " +
				"    <stix:Exploit_Targets> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:ExploitTarget-71c0bdac-4a55-4143-87e8-afee94aa2460\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Vulnerability> " +
				"                <et:Title>Title 1</et:Title> " +
				"                <et:Description>Description 1</et:Description> " +
				"            </et:Vulnerability> " +
				"            <et:Related_Exploit_Targets> " +
				"                <et:Related_Exploit_Target> " +
				"                    <stixCommon:Exploit_Target " +
				"                        idref=\"stucco:ExploitTarget-fd4c5589-b1ac-433d-a5a1-ffc438a5cad4\" xsi:type=\"et:ExploitTargetType\"/> " +
				"                </et:Related_Exploit_Target> " +
				"            </et:Related_Exploit_Targets> " +
				"        </stixCommon:Exploit_Target> " +
				"        <stixCommon:Exploit_Target " +
				"            id=\"stucco:ExploitTarget-fd4c5589-b1ac-433d-a5a1-ffc438a5cad4\" " +
				"            xmlns:stucco=\"gov.ornl.stucco\" " +
				"            xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"et:ExploitTargetType\"> " +
				"            <et:Vulnerability> " +
				"                <et:Title>Title 2</et:Title> " +
				"                <et:Description>Description 2</et:Description> " +
				"            </et:Vulnerability> " +
				"        </stixCommon:Exploit_Target> " +
				"    </stix:Exploit_Targets> " +
				"</stix:STIX_Package> ";

			/* normalize stix package */
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIX preprocessSTIX = new PreprocessSTIX();
			Map<String, Element> stixElements = preprocessSTIX.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);
			ExploitTarget oldET = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(0);
			ExploitTarget newET = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(1);
			String id = oldET.getId().getLocalPart();
			if (!id.equals("ExploitTarget-71c0bdac-4a55-4143-87e8-afee94aa2460")) {
				oldET = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(1);
				newET = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(0);
			}

			System.out.println("Testing Exploit_Target ...");
			Element normalizedElement = stixElements.get("stucco:ExploitTarget-71c0bdac-4a55-4143-87e8-afee94aa2460");
			String normalizedETString = new XMLOutputter().outputString(normalizedElement);
			ExploitTarget normalizedET = new ExploitTarget().fromXMLString(normalizedETString);
			assertTrue(normalizedET.validate());
			normalizedET.setRelatedExploitTargets(null);
			oldET.setRelatedExploitTargets(null);
			assertTrue(oldET.equals(normalizedET));

			System.out.println("Testing Exploit_Target ...");
			stixElements.remove("stucco:ExploitTarget-71c0bdac-4a55-4143-87e8-afee94aa2460");
			for (String key : stixElements.keySet()) {
				normalizedElement = stixElements.get(key);
			}
			normalizedETString = new XMLOutputter().outputString(normalizedElement);
			normalizedET = new ExploitTarget().fromXMLString(normalizedETString);
			normalizedET.setId(null);
			newET.setId(null);
			assertTrue(normalizedET.validate());
			assertTrue(newET.equals(normalizedET));

		} catch (SAXException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}



