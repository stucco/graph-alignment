package gov.ornl.stucco.preprocessors;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import javax.xml.namespace.QName;					
 
import org.xml.sax.SAXException; 

import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.cybox.cybox_2.Observable; 
import org.mitre.cybox.cybox_2.Observables; 
import org.mitre.stix.courseofaction_1.CourseOfAction;  
import org.mitre.stix.indicator_2.Indicator;   
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.campaign_1.Campaign;
import org.mitre.stix.exploittarget_1.ExploitTarget; 
import org.mitre.stix.incident_1.Incident;
import org.mitre.stix.threatactor_1.ThreatActor;
import org.mitre.stix.common_1.IndicatorBaseType;

import java.io.File;
import java.io.StringReader; 
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.jdom2.output.XMLOutputter;
import org.jdom2.output.Format; 
import org.jdom2.Document;
import org.jdom2.Element; 
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.JDOMException;
import org.jdom2.input.StAXStreamBuilder;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
 
public class PreprocessSTIXTest { 
	
	/*
  * Parses xml String and converts it to jdom2 Document
  */ 
  private static Document parseXMLText(String documentText) {
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

  /*
   * Used to validate normalized stix elements
   */
	private void validate(Map<String, PreprocessSTIX.Vertex> vertices) {
		try {
		  for (String id : vertices.keySet()) {
		    PreprocessSTIX.Vertex v = vertices.get(id);
		    String xml = v.xml;
		    if (v.type.equals("Observable")) {
		    	count++;
		      Observable ob = new Observable().fromXMLString(xml);
		      if (!ob.validate()) {
		      	System.out.println(ob.toXMLString(true));
		      }
		      // System.out.println(ob.validate());
		    } else if (v.type.equals("Indicator")) {
		    	count++;
		      Indicator ob = new Indicator().fromXMLString(xml);
		      if (!ob.validate()) {
		      	System.out.println(ob.toXMLString(true));
		      }
		      // System.out.println(ob.validate());
		    } else if (v.type.equals("Incident")) {
		    	count++;
		      Incident ob = new Incident().fromXMLString(xml);
		      if (!ob.validate()) {
		      	System.out.println(ob.toXMLString(true));
		      }
		      //System.out.println(ob.validate());
		    } else if (v.type.equals("TTP")) {
		    	count++;
		    	TTP ttp = new TTP().fromXMLString(xml);
		      if (!ttp.validate()) {
		      	System.out.println(ttp.toXMLString(true));
		      }
		    	//System.out.println(ttp.validate());
		    } else if (v.type.equals("Campaign")) {
		    	count++;
		    	Campaign camp = new Campaign().fromXMLString(xml);
		      if (!camp.validate()) {
		      	System.out.println(camp.toXMLString(true));
		      }
		    	// System.out.println(camp.validate());
		    } else if (v.type.equals("Threat_Actor")) {
		    	count++;
		    	ThreatActor ta = new ThreatActor().fromXMLString(xml);
		      if (!ta.validate()) {
		      	System.out.println(ta.toXMLString(true));
		      }
		    	// System.out.println(ta.validate());
		    } else if (v.type.equals("Exploit_Target")) {
		    	count++;
		    	ExploitTarget et = new ExploitTarget().fromXMLString(xml);
		      if (!et.validate()) {
		      	System.out.println(et.toXMLString(true));
		      }
		    	// System.out.println(et.validate());
		    } else if (v.type.equals("Course_Of_Action")) {
		    	count++;
		    	CourseOfAction coa = new CourseOfAction().fromXMLString(xml);
		      if (!coa.validate()) {
		      	System.out.println(coa.toXMLString(true));
		      }
		    	// System.out.println(coa.validate());
		    } else {
		    	System.out.println("COULD NOT FIND -------------- > " + v.type);
		    }

		  }
		} catch (SAXException e) {
		  e.printStackTrace();
		}
	}

  /*
	 * Tests normalize cybox: contains Observable_Composition
	 */
	@Test
	public void test_normalize_observable_composition() {

		System.out.println("gov.ornl.stucco.preprocessors.test_normalize_observable_composition()");

				String testStixString = 
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

				String expectedStixString = 
					"  <cybox:Observables xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
					"   xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
					"   xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\" " +
					"   xmlns:WinRegistryKeyObj=\"http://cybox.mitre.org/objects#WinRegistryKeyObject-2\" " +
					"   xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
					"   xmlns:example=\"http://example.com/\" " +
					"   cybox_major_version=\"2\"  cybox_minor_version=\"1\"> " +
					"     <cybox:Observable id=\"example:f6bb0360-46ac-49b9-9ca1-9008e937ea24\"> " +
					"       <cybox:Observable_Composition operator=\"AND\"> " +
					"         <cybox:Observable idref=\"example:ca588488-5900-401e-b02f-0080d83e2472\" /> " +
					"         <cybox:Observable idref=\"example:b1fc168c-c9be-4b4a-925e-206b9afed76a\" /> " +
					"       </cybox:Observable_Composition> " +
					"     </cybox:Observable> " +
					"     <cybox:Observable id=\"example:ca588488-5900-401e-b02f-0080d83e2472\"> " +
					"       <cybox:Object> " +
					"         <cybox:Properties xsi:type=\"FileObj:FileObjectType\"> " +
					"           <FileObj:File_Path condition=\"Contains\" fully_qualified=\"false\">system32\twext.exe</FileObj:File_Path> " +
					"         </cybox:Properties> " +
					"       </cybox:Object> " +
					"    	</cybox:Observable> " +
					"     <cybox:Observable id=\"example:b1fc168c-c9be-4b4a-925e-206b9afed76a\"> " +
					"       <cybox:Object> " +
					"         <cybox:Properties xsi:type=\"WinRegistryKeyObj:WindowsRegistryKeyObjectType\"> " +
					"           <WinRegistryKeyObj:Key condition=\"Equals\">Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon</WinRegistryKeyObj:Key> " +
					"             <WinRegistryKeyObj:Hive condition=\"Equals\">HKEY_LOCAL_MACHINE</WinRegistryKeyObj:Hive> " +
					"             <WinRegistryKeyObj:Values> " +
					"               <WinRegistryKeyObj:Value> " +
					"                 <WinRegistryKeyObj:Name condition=\"Equals\">Userinit</WinRegistryKeyObj:Name> " +
					"                 <WinRegistryKeyObj:Data condition=\"Contains\">system32\\twext.exe</WinRegistryKeyObj:Data> " +
					"               </WinRegistryKeyObj:Value> " +
					"             </WinRegistryKeyObj:Values> " +
					"           </cybox:Properties> " +
					"         </cybox:Object> " +
					"       </cybox:Observable> " +
					"  </cybox:Observables> ";

			/* normalize stix package */
			System.out.println();
			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(testStixString);
			validate(vertices);
			assertTrue(vertices.size() == 3);

			Observables observables = new Observables().fromXMLString(expectedStixString);
			List<Observable> list = observables.getObservables();
			for (Observable observable : list) {
				System.out.println("Testing Observable ... ");
				QName id = observable.getId();
				String prefix = id.getPrefix();
				String localPart = id.getLocalPart();
				String expectedId = prefix + ":" + localPart;
				assertTrue(vertices.containsKey(expectedId));

				Observable expectedObservable = Observable.fromXMLString(vertices.get(expectedId).xml);
				boolean equal = observable.equals(expectedObservable);

				assertTrue(observable.equals(expectedObservable));
			}
	}
	
	/*
	 * Tests normalize cybox: contains Related_Object
	 */
	@Test
	public void test_normalize_related_object() {

		System.out.println("gov.ornl.stucco.preprocessors.test_normalize_related_object()");

			String testStixString = 
				"    <cybox:Observables xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +        
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\"  " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\"  " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\"  " +
				"    xmlns:EmailMessageObj=\"http://cybox.mitre.org/objects#EmailMessageObject-2\"  " +
				"    xmlns:cyboxVocabs=\"http://cybox.mitre.org/default_vocabularies-2\"  " +                
				"    xmlns:example=\"http://example.com\"  " +
				"    xsi:schemaLocation=\"  " +    
				"    http://cybox.mitre.org/cybox-2 ../../../cybox/cybox_core.xsd  " +
				"    http://cybox.mitre.org/common-2 ../../../cybox/cybox_common.xsd " +
				"    http://cybox.mitre.org/objects#AddressObject-2 ../../../cybox/objects/Address_Object.xsd " +
				"    http://cybox.mitre.org/objects#FileObject-2 ../../../cybox/objects/File_Object.xsd " +
				"    http://cybox.mitre.org/objects#EmailMessageObject-2 ../../../cybox/objects/Email_Message_Object.xsd " +
				"    http://cybox.mitre.org/default_vocabularies-2 ../../../cybox/cybox_default_vocabularies.xsd\"  " +
				"    cybox_major_version=\"2\" cybox_minor_version=\"1\"> " +
				"    <cybox:Observable id=\"example:observable-pattern-5f1dedd3-ece3-4007-94cd-7d52784c1474\"> " +
				"             <cybox:Object id=\"example:object-3a7aa9db-d082-447c-a422-293b78e24238\"> " +
				"                    <cybox:Properties xsi:type=\"EmailMessageObj:EmailMessageObjectType\"> " +
				"                        <EmailMessageObj:Header> " +
				"                            <EmailMessageObj:From id=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed300\" category=\"e-mail\"> " +
				"                                <AddressObj:Address_Value condition=\"Contains\">@state.gov</AddressObj:Address_Value> " +
				"                            </EmailMessageObj:From> " +
				"                        </EmailMessageObj:Header> " +
				"                    </cybox:Properties> " +
				"                    <cybox:Related_Objects> " +
				"                        <cybox:Related_Object> " +
				"                                     <cybox:Properties xsi:type=\"FileObj:FileObjectType\" id=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed288\" > " +
				"                                       <FileObj:File_Extension>pdf</FileObj:File_Extension> " +
				"                                      <FileObj:Size_In_Bytes>87022</FileObj:Size_In_Bytes> " +
				"                                      <FileObj:Hashes> " +
				"                                            <cyboxCommon:Hash> " +
				"                                                 <cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"                                                 <cyboxCommon:Simple_Hash_Value>cf2b3ad32a8a4cfb05e9dfc45875bd70</cyboxCommon:Simple_Hash_Value> " +
				"                                            </cyboxCommon:Hash> " +
				"                                      </FileObj:Hashes> " +
				"                                     </cybox:Properties> " +
				"                                     <cybox:Relationship xsi:type=\"cyboxVocabs:ObjectRelationshipVocab-1.0\">Contains</cybox:Relationship> " +
				"                        </cybox:Related_Object> " +
				"                    </cybox:Related_Objects> " +
				"                </cybox:Object> " +
				"        </cybox:Observable>   " +
				"    </cybox:Observables>  ";

			String expectedStixString = 
				"    <cybox:Observables xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +        
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\"  " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\"  " +
				"    xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\" " +
				"    xmlns:FileObj=\"http://cybox.mitre.org/objects#FileObject-2\"  " +
				"    xmlns:EmailMessageObj=\"http://cybox.mitre.org/objects#EmailMessageObject-2\"  " +
				"    xmlns:cyboxVocabs=\"http://cybox.mitre.org/default_vocabularies-2\"  " +                
				"    xmlns:example=\"http://example.com\"  " +
				"    xsi:schemaLocation=\"  " +    
				"    http://cybox.mitre.org/cybox-2 ../../../cybox/cybox_core.xsd  " +
				"    http://cybox.mitre.org/common-2 ../../../cybox/cybox_common.xsd " +
				"    http://cybox.mitre.org/objects#AddressObject-2 ../../../cybox/objects/Address_Object.xsd " +
				"    http://cybox.mitre.org/objects#FileObject-2 ../../../cybox/objects/File_Object.xsd " +
				"    http://cybox.mitre.org/objects#EmailMessageObject-2 ../../../cybox/objects/Email_Message_Object.xsd " +
				"    http://cybox.mitre.org/default_vocabularies-2 ../../../cybox/cybox_default_vocabularies.xsd\"  " +
				"    cybox_major_version=\"2\" cybox_minor_version=\"1\"> " +
				"    <cybox:Observable id=\"example:observable-pattern-5f1dedd3-ece3-4007-94cd-7d52784c1474\"> " +
				"             <cybox:Object id=\"example:object-3a7aa9db-d082-447c-a422-293b78e24238\"> " +
				"                    <cybox:Properties xsi:type=\"EmailMessageObj:EmailMessageObjectType\"> " +
				"                        <EmailMessageObj:Header> " +
				"                            <EmailMessageObj:From object_reference=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed300\" /> " +
				"                        </EmailMessageObj:Header> " +
				"                    </cybox:Properties> " +
				"                    <cybox:Related_Objects> " +
				"                        <cybox:Related_Object> " +
				"                        	<cybox:Properties xsi:type=\"FileObj:FileObjectType\" object_reference=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed288\" /> " +
				"                         <cybox:Relationship xsi:type=\"cyboxVocabs:ObjectRelationshipVocab-1.0\">Contains</cybox:Relationship> " +
				"                        </cybox:Related_Object> " +
				"                    </cybox:Related_Objects> " +
				"                </cybox:Object> " +
				"        </cybox:Observable> " +
				"       <cybox:Observable id=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed288\"> " +
				"					<cybox:Object> " +
				"         	<cybox:Properties xsi:type=\"FileObj:FileObjectType\" > " +
				"           	<FileObj:File_Extension>pdf</FileObj:File_Extension> " +
				"           	<FileObj:Size_In_Bytes>87022</FileObj:Size_In_Bytes> " +
				"           	<FileObj:Hashes> " +
				"           		<cyboxCommon:Hash> " +
				"           			<cyboxCommon:Type>MD5</cyboxCommon:Type> " +
				"           			<cyboxCommon:Simple_Hash_Value>cf2b3ad32a8a4cfb05e9dfc45875bd70</cyboxCommon:Simple_Hash_Value> " +
				"           		</cyboxCommon:Hash> " +
				"           	</FileObj:Hashes> " +
				"           </cybox:Properties> " +
				"					</cybox:Object> " +
				"       </cybox:Observable> " +
				"				<cybox:Observable xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"				xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\"  " +
				"				xmlns:example=\"http://example.com\"  " +
				"				xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"  " +
				"				id=\"example:Observable-da0360a3-a71e-4f98-a408-2147045ed300\"> " +
				"					<cybox:Object> " +
				"						<cybox:Properties xsi:type=\"AddressObj:AddressObjectType\"> " +
				"							<AddressObj:Address_Value condition=\"Contains\">@state.gov</AddressObj:Address_Value> " +
				"						</cybox:Properties> " +
				"					</cybox:Object> " +
				"				</cybox:Observable> " +
				"    </cybox:Observables>  ";

			/* normalize stix package */
			System.out.println();
			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(testStixString);
			validate(vertices);

			Observables observables = new Observables().fromXMLString(expectedStixString);
			List<Observable> list = observables.getObservables();
			for (Observable observable : list) {
				System.out.println("Testing Observable ... ");
				QName id = observable.getId();
				String prefix = id.getPrefix();
				String localPart = id.getLocalPart();
				String expectedId = prefix + ":" + localPart;
				assertTrue(vertices.containsKey(expectedId));

				Observable expectedObservable = Observable.fromXMLString(vertices.get(expectedId).xml);
				boolean equal = observable.equals(expectedObservable);

				assertTrue(observable.equals(expectedObservable));
			}
	}

	/*
	 * Tests normalize stix: Incident with Indicator, Observable, TTP, and ExploitTarget
	 */
	@Test
	public void test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget() {

		System.out.println("gov.ornl.stucco.preprocessors.test_normalizeSTIX_Incident_with_Indicator_Observable_TTP_ExploitTarget()");
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

			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);

			System.out.println("Testing Indicator ...");
			Indicator expectedIndicator = (Indicator) expectedElements.getIndicators().getIndicators().get(0);
			QName qname = expectedIndicator.getId();
			String id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			Indicator normalizedIndicator = new Indicator().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedIndicator.validate());
			assertTrue(expectedIndicator.equals(normalizedIndicator));


			System.out.println("Testing TTP ...");
			TTP expectedTtp = (TTP) expectedElements.getTTPs().getTTPS().get(0);
			qname = expectedTtp.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			TTP normalizedTtp = new TTP().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedTtp.validate());
			assertTrue(expectedTtp.equals(normalizedTtp));

			System.out.println("Testing Incident ...");
			Incident expectedIncident = (Incident) expectedElements.getIncidents().getIncidents().get(0);
			qname = expectedIncident.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			Incident normalizedIncident = new Incident().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedIncident.validate());
			assertTrue(expectedIncident.equals(normalizedIncident));

			System.out.println("Testing Observable ...");
			Observable expectedObservable = expectedElements.getObservables().getObservables().get(0);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			Observable normalizedObservable = new Observable().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));			

			System.out.println("Testing Observable ...");
			expectedObservable = expectedElements.getObservables().getObservables().get(1);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			normalizedObservable = new Observable().fromXMLString(vertices.get(id).xml);
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

		System.out.println("gov.ornl.stucco.preprocessors.test_normalizeSTIX_ExploitTarget_Observables_COA()");
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

			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(testStixString);

			STIXPackage expectedElements = new STIXPackage().fromXMLString(expectedStixString);

			System.out.println("Testing ExploitTarget ...");
			ExploitTarget expectedEt = (ExploitTarget) expectedElements.getExploitTargets().getExploitTargets().get(0);
			QName qname = expectedEt.getId();
			String id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			ExploitTarget normalizedEt = new ExploitTarget().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedEt.validate());
			assertTrue(expectedEt.equals(normalizedEt));

			System.out.println("Testing Observable ...");
			Observable expectedObservable = expectedElements.getObservables().getObservables().get(0);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			Observable normalizedObservable = new Observable().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));			

			System.out.println("Testing Observable ...");
			expectedObservable = expectedElements.getObservables().getObservables().get(1);
			qname = expectedObservable.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			normalizedObservable = new Observable().fromXMLString(vertices.get(id).xml);
			assertTrue(normalizedObservable.validate());
			assertTrue(expectedObservable.equals(normalizedObservable));	

			System.out.println("Testing CourseOfAction ...");
			CourseOfAction expectedCoa = (CourseOfAction) expectedElements.getCoursesOfAction().getCourseOfActions().get(0);
			qname = expectedCoa.getId();
			id = qname.getPrefix() + ":" + qname.getLocalPart();
			assertTrue(vertices.containsKey(id));
			CourseOfAction normalizedCoa = new CourseOfAction().fromXMLString(vertices.get(id).xml);
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

		System.out.println("gov.ornl.stucco.preprocessors.test_normalizeSTIX_Indicator_Observable()");
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
			
			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(testStixString);

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
			String xml = vertices.get("stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a").xml;
			Indicator normalizedIndicator = new Indicator().fromXMLString(xml);
			assertTrue(normalizedIndicator.validate());
			assertTrue(outerIndicator.equals(normalizedIndicator));
			vertices.remove("stucco:Indicator-3dfd38e7-12cb-4e5a-b5e7-54b369ebcd7a");

			System.out.println("Testing Indicator ... ");
			xml = vertices.get("stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225").xml;
			normalizedIndicator = new Indicator().fromXMLString(xml);
			assertTrue(normalizedIndicator.validate());
			assertTrue(innerIndicator.equals(normalizedIndicator));
			vertices.remove("stucco:Indicator-450a49ab-584a-4059-a7e7-cc715dc2d225");

			System.out.println("Testing Unix Account ... ");
			xml = vertices.get("stucco:Observable-67029ece-7402-46ba-83fa-ba27e81dc7c7").xml;

			Element normalizedElement = parseXMLText(xml).getRootElement();
			Element object = normalizedElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element properties = object.getChild("Properties", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element pid = properties.getChild("PID", Namespace.getNamespace("ProcessObj","http://cybox.mitre.org/objects#ProcessObject-2"));
			assertEquals(pid.getText(), "pid");
			Element name = properties.getChild("Name", Namespace.getNamespace("ProcessObj","http://cybox.mitre.org/objects#ProcessObject-2"));
			assertEquals(name.getText(), "Unix Process Name");
			Element portList = properties.getChild("Port_List", Namespace.getNamespace("ProcessObj", "http://cybox.mitre.org/objects#ProcessObject-2"));
			Element port = portList.getChild("Port", Namespace.getNamespace("ProcessObj", "http://cybox.mitre.org/objects#ProcessObject-2"));
			String portIdref = port.getAttributeValue("object_reference");
			assertTrue(vertices.containsKey(portIdref));
			Element sessionId = properties.getChild("Session_ID", Namespace.getNamespace("UnixProcessObj", "http://cybox.mitre.org/objects#UnixProcessObject-2"));
			assertEquals(sessionId.getText(), "123");

			System.out.println("Testing Port ... ");
			xml = vertices.get(portIdref).xml;

			normalizedElement = parseXMLText(xml).getRootElement();
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
	 * Tests normalize cybox: extracting Address from Flow, IP from Address, Port from Address
	 */
	@Test
	public void test_flow_address_ip_port() {
		System.out.println("gov.ornl.stucco.preprocessors.test_flow_address_ip_port()");
		
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

			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(xml);
			validate(vertices);

			assertTrue(vertices.size() == 7);

			System.out.println("Testing Flow -> Source Address ... ");
			Element observableElement = parseXMLText(vertices.get("Observable-0a02b096-a29c-4d09-b75b-508ffoy6d08b").xml).getRootElement();

			Element object = observableElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			Element properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			Element networkFlowLabel = properties.getChild("Network_Flow_Label", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Element sourceSocketAddress = networkFlowLabel.getChild("Src_Socket_Address", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Attribute srcIdrefAttr = sourceSocketAddress.getAttribute("object_reference");
			assertNotNull(srcIdrefAttr);
			String srcIdref = srcIdrefAttr.getValue();
			assertTrue(vertices.containsKey(srcIdref));

			System.out.println("Testing Flow -> Description Address ... ");
			Element destSocketAddress = networkFlowLabel.getChild("Dest_Socket_Address", Namespace.getNamespace("NetFlowObj","http://cybox.mitre.org/objects#NetworkFlowObject-2"));
			Attribute destIdrefAttr = destSocketAddress.getAttribute("object_reference");
			assertNotNull(destIdrefAttr);
			String destIdref = destIdrefAttr.getValue();
			assertTrue(vertices.containsKey(destIdref));

			System.out.println("Testing (Source) Address ... ");
			Element sourceSocketElement = parseXMLText(vertices.get(srcIdref).xml).getRootElement();
			object = sourceSocketElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));

			System.out.println("Testing (Source) Address -> IP ...");
			Element ipAddress = properties.getChild("IP_Address", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute sourceIpIdref = ipAddress.getAttribute("object_reference");
			assertNotNull(sourceIpIdref);
			String sourceIpId = sourceIpIdref.getValue();
			assertTrue(vertices.containsKey(sourceIpId));
			System.out.println("Testing (Source) Address -> Port ...");
			Element portAddress = properties.getChild("Port", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute sourcePortIdref = portAddress.getAttribute("object_reference");
			assertNotNull(sourcePortIdref);
			String sourcePortId = sourcePortIdref.getValue();
			assertTrue(vertices.containsKey(sourcePortId));

			System.out.println("Testing (Source) IP ... ");
			Element sourceIpElement = parseXMLText(vertices.get(sourceIpId).xml).getRootElement();
			object = sourceIpElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			ipAddress = properties.getChild("Address_Value", Namespace.getNamespace("AddressObj", "http://cybox.mitre.org/objects#AddressObject-2"));
			assertEquals(ipAddress.getText(), "000.000.000.111");

			System.out.println("Testing (Source) Port ... ");
			Element sourcePortElement = parseXMLText(vertices.get(sourcePortId).xml).getRootElement();
			object = sourcePortElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			portAddress = properties.getChild("Port_Value", Namespace.getNamespace("PortObj", "http://cybox.mitre.org/objects#PortObject-2"));
			assertEquals(portAddress.getText(), "11");

			System.out.println("Testing (Destination) Address ... ");
			Element destSocketElement = parseXMLText(vertices.get(destIdref).xml).getRootElement();
			object = destSocketElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));

			System.out.println("Testing (Destination) Address -> IP ...");
			ipAddress = properties.getChild("IP_Address", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute destIpIdref = ipAddress.getAttribute("object_reference");
			assertNotNull(destIpIdref);
			String destIpId = destIpIdref.getValue();
			assertTrue(vertices.containsKey(destIpId));

			System.out.println("Testing (Destination) Address -> Port ...");
			portAddress = properties.getChild("Port", Namespace.getNamespace("SocketAddressObj", "http://cybox.mitre.org/objects#SocketAddressObject-1"));
			Attribute destPortIdref = portAddress.getAttribute("object_reference");
			assertNotNull(destPortIdref);
			String destPortId = destPortIdref.getValue();
			assertTrue(vertices.containsKey(destPortId));

			System.out.println("Testing (Destination) IP ... ");
			Element destIpElement = parseXMLText(vertices.get(destIpId).xml).getRootElement();
			object = destIpElement.getChild("Object", Namespace.getNamespace("cybox", "http://cybox.mitre.org/cybox-2"));
			properties = object.getChild("Properties", Namespace.getNamespace("cybox","http://cybox.mitre.org/cybox-2"));
			ipAddress = properties.getChild("Address_Value", Namespace.getNamespace("AddressObj", "http://cybox.mitre.org/objects#AddressObject-2"));
			assertEquals(ipAddress.getText(), "000.000.000.222");

			System.out.println("Testing (Destination) Port ... ");
			Element destPortElement = parseXMLText(vertices.get(destPortId).xml).getRootElement();
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
	@Test
	public void test_httpsession_dnsrecord_address_ip_port_domainname() {
		System.out.println("gov.ornl.stucco.preprocessors.test_dnsrecord_address_ip_port_domainname()");
		
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

			PreprocessSTIX sp = new PreprocessSTIX();
			Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(xml);
			validate(vertices);

			assertTrue(vertices.size() == 13);

		} catch (Exception e) { 
			e.printStackTrace();
			fail("Exception");
		}
	}

	/*
	 * Tests normalize stix: TTP with multiple Malware and Exploits
	 */
	//@Test
	public void test_normalizeSTIX_TTP_Malware() {
		System.out.println("gov.ornl.stucco.preprocessors.test_normalizeSTIX_TTP_Malware()");

		//try {
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
/*
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
		*/
	}

	/*
	 * Tests normalize stix: TTP with multiple Exploits
	 */
	//@Test
	public void test_normalizeSTIX_TTP_Exploits() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_TTP()");
		/*
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
		*/
	}

	/*
	 * Tests normalize stix: Exploit Target with multiple Vulnerabilities
	 */
	//@Test
	public void test_normalizeSTIX_ExploitTarget_Vulnerability() {

		System.out.println("alignment.alignment_v2.test_normalizeSTIX_ExploitTarget_Vulnerability()");
		/*
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
		*/
	}

	int count = 0;
  //@Test
	public void test_samples() {
		normalizeContents(new File("./samples"));
		assertTrue(true);
		System.out.println("count = " + count);
	}

	private void normalizeContents(File dir) {
		try {
			File[] files = dir.listFiles();
			for (File file : files) {
				if (file.isDirectory()) {
					System.out.println("directory:" + file.getCanonicalPath());
					normalizeContents(file);
				} else {
					System.out.println("     file:" + file.getCanonicalPath());
					String path = file.getPath();
					if (path.endsWith("xml")) {
						String content = new String(Files.readAllBytes(Paths.get(file.getPath())));
						// System.out.println(content);
						PreprocessSTIX sp = new PreprocessSTIX();
						Map<String, PreprocessSTIX.Vertex> vertices = sp.normalizeSTIX(content);
						validate(vertices);
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}



