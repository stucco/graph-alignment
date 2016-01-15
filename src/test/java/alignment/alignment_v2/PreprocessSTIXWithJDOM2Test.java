package alignment.alignment_v2;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.File;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Set;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.XML;
import org.junit.Test;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;					
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException; 
import org.xml.sax.SAXParseException;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Attribute;
import org.jdom2.Namespace;
import org.jdom2.xpath.*;
import org.jdom2.filter.Filters;

import org.apache.commons.io.FileUtils;

public class PreprocessSTIXWithJDOM2Test extends PreprocessSTIXwithJDOM2 {
	
	/**
	 * Tests normalize stix: Incident with Indicator, Observable, TTP, and ExploitTarget
	 */
	@Test
	public void test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
		try {
			String initialStixString =
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
				"        <cybox:Observable id=\"stucco:Observable-6700\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"        </cybox:Observable> " +
				"        <cybox:Observable id=\"stucco:Observable-6789\"> " +
				"            <cybox:Title>Observable - Title</cybox:Title> " +
				"            <cybox:Observable_Source> " +
				"                <cyboxCommon:Information_Source_Type>Source</cyboxCommon:Information_Source_Type> " +
				"            </cybox:Observable_Source> " +
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
				"        <stix:Incident  id=\"stucco:Incident-6400\" " +
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

			JSONObject json = xmlToJson(expectedStixString);

			/* normalize stix package */
			System.out.println();
			System.out.println("Testing Normalized STIX Package");
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();
			assertTrue(normalizedStixPackage.validate());
			STIXPackage expectedStixPackage = STIXPackage.fromXMLString(expectedStixString);
			assertTrue(normalizedStixPackage.equals(expectedStixPackage));
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}


	/**
	 * Tests normalize stix: ExploitTarget with Observable and COA
	 */
	@Test
	public void test_normalizeSTIX_ExploitTarget_with_Observable_COA() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_ExploitTarget_with_Observable_COA()");
		try {
			String initialStixString =
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
			PreprocessSTIXwithJDOM2 preprocessSTIX = new PreprocessSTIXwithJDOM2();
			preprocessSTIX.normalizeSTIXPackage(initialStixString);
			STIXPackage normalizedStixPackage = preprocessSTIX.getSTIXPackage();
			assertTrue(normalizedStixPackage.validate());
			
			STIXPackage expectedStixPackage = STIXPackage.fromXMLString(expectedStixString);
			assertTrue(normalizedStixPackage.equals(expectedStixPackage));
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
}



