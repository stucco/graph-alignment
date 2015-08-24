package alignment.alignment_v2;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Map;

import org.json.JSONObject;
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
import org.xml.sax.helpers.*;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Entity;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

//import HTMLExtractor.HTMLExtractor;


public class PreprocessSTIXTest extends PreprocessSTIX{

	/**
	 * Tests flattenSTIX method
	 */
	@Test
	public void testConvert_flattenSTIX(){
		try {
			
			String STIXString = 
				"<stix:STIX_Package " +
				"    id=\"mandiant:package-190593d6-1861-4cfe-b212-c016fce1e242\" " +
				"    version=\"1.2\" " +
				"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:report=\"http://stix.mitre.org/Report-1\" " +
				"    xmlns:stixVocabs=\"http://stix.mitre.org/default_vocabularies-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:cyboxVocabs=\"http://cybox.mitre.org/default_vocabularies-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:ttp=\"http://stix.mitre.org/TTP-1\" " +
				"    xmlns:marking=\"http://data-marking.mitre.org/Marking-1\" " +
				"    xmlns:terms=\"http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1\" " +
				"    xmlns:mandiant=\"http://www.mandiant.com\" " +
				"    xmlns:DomainNameObj=\"http://cybox.mitre.org/objects#DomainNameObject-1\" " +
				"    xsi:schemaLocation=\" " +
				"    http://stix.mitre.org/stix-1 http://stix.mitre.org/XMLSchema/core/1.2/stix_core.xsd " +
				"    http://stix.mitre.org/Report-1 http://stix.mitre.org/XMLSchema/report/1.0/report.xsd " +
				"    http://stix.mitre.org/default_vocabularies-1 http://stix.mitre.org/XMLSchema/default_vocabularies/1.2.0/stix_default_vocabularies.xsd " +
				"    http://stix.mitre.org/common-1 http://stix.mitre.org/XMLSchema/common/1.2/stix_common.xsd " +
				"    http://data-marking.mitre.org/Marking-1 http://stix.mitre.org/XMLSchema/data_marking/1.2/data_marking.xsd " +
				"    http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd " +
				"    http://cybox.mitre.org/default_vocabularies-2 http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd " +
				"    http://stix.mitre.org/Indicator-2 http://stix.mitre.org/XMLSchema/indicator/2.2/indicator.xsd " +
				"    http://stix.mitre.org/TTP-1 http://stix.mitre.org/XMLSchema/ttp/1.2/ttp.xsd " +
				"    http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1 http://stix.mitre.org/XMLSchema/extensions/marking/terms_of_use/1.1/terms_of_use_marking.xsd " +
				"    http://cybox.mitre.org/objects#URIObject-2 http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd " +
				"    \"> " +
				"    <stix:STIX_Header> " +
				"        <stix:Handling> " +
				"            <marking:Marking> " +
				"                <marking:Controlled_Structure>//node() | //@*</marking:Controlled_Structure> " +
				"                <marking:Marking_Structure xsi:type=\"terms:TermsOfUseMarkingStructureType\"> " +
				"                    <terms:Terms_Of_Use>APT1: Exposing One of China's Cyber Espionage Units (the \"APT1 Report\") is copyright 2013 by Mandiant Corporation and can be downloaded at intelreport.mandiant.com.  This XML file using the STIX standard was created by The MITRE Corporation using the content of the APT1 Report with Mandiant's permission.  Mandiant is not responsible for the content of this file.</terms:Terms_Of_Use> " +
				"                </marking:Marking_Structure> " +
				"            </marking:Marking> " +
				"        </stix:Handling> " +
				"        <stix:Information_Source> " +
				"            <stixCommon:Identity> " +
				"                <stixCommon:Name>MITRE</stixCommon:Name> " +
				"            </stixCommon:Identity> " +
				"            <stixCommon:Role xsi:type=\"stixVocabs:InformationSourceRoleVocab-1.0\">Transformer/Translator</stixCommon:Role> " +
				"            <stixCommon:Contributing_Sources> " +
				"                <stixCommon:Source> " +
				"                    <stixCommon:Identity> " +
				"                        <stixCommon:Name>Mandiant</stixCommon:Name> " +
				"                    </stixCommon:Identity> " +
				"                    <stixCommon:Role xsi:type=\"stixVocabs:InformationSourceRoleVocab-1.0\">Initial Author</stixCommon:Role> " +
				"                    <stixCommon:Time> " +
				"                        <cyboxCommon:Produced_Time precision=\"day\">2013-02-19T00:00:00Z</cyboxCommon:Produced_Time> " +
				"                    </stixCommon:Time> " +
				"                </stixCommon:Source> " +
				"            </stixCommon:Contributing_Sources> " +
				"            <stixCommon:Time> " +
				"                <cyboxCommon:Produced_Time precision=\"day\">2014-01-16T00:00:00Z</cyboxCommon:Produced_Time> " +
				"            </stixCommon:Time> " +
				"            <stixCommon:References> " +
				"                <stixCommon:Reference>http://intelreport.mandiant.com/Mandiant_APT1_Report.pdf</stixCommon:Reference> " +
				"            </stixCommon:References> " +
				"        </stix:Information_Source> " +
				"    </stix:STIX_Header> " +
				"</stix:STIX_Package>";
			
			//strip whitespace
			while(STIXString.contains("> ")){
				STIXString = STIXString.replaceAll("> ", ">");
			}
			while(STIXString.contains(" <")){
				STIXString = STIXString.replaceAll(" <", "<");
			}

			STIXPackage testPackage = STIXPackage.fromXMLString(STIXString);
			
			assertTrue(PreprocessSTIX.validate(testPackage));
			
			String expectedNormalizedSTIXString =
				"<stix:STIX_Package " +
				"    id=\"mandiant:package-190593d6-1861-4cfe-b212-c016fce1e242\" " +
				"    version=\"1.2\" " +
				"    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
				"    xmlns:stix=\"http://stix.mitre.org/stix-1\" " +
				"    xmlns:report=\"http://stix.mitre.org/Report-1\" " +
				"    xmlns:stixVocabs=\"http://stix.mitre.org/default_vocabularies-1\" " +
				"    xmlns:stixCommon=\"http://stix.mitre.org/common-1\" " +
				"    xmlns:cybox=\"http://cybox.mitre.org/cybox-2\" " +
				"    xmlns:cyboxCommon=\"http://cybox.mitre.org/common-2\" " +
				"    xmlns:cyboxVocabs=\"http://cybox.mitre.org/default_vocabularies-2\" " +
				"    xmlns:indicator=\"http://stix.mitre.org/Indicator-2\" " +
				"    xmlns:ttp=\"http://stix.mitre.org/TTP-1\" " +
				"    xmlns:marking=\"http://data-marking.mitre.org/Marking-1\" " +
				"    xmlns:terms=\"http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1\" " +
				"    xmlns:mandiant=\"http://www.mandiant.com\" " +
				"    xmlns:DomainNameObj=\"http://cybox.mitre.org/objects#DomainNameObject-1\" " +
				"    xsi:schemaLocation=\" " +
				"    http://stix.mitre.org/stix-1 http://stix.mitre.org/XMLSchema/core/1.2/stix_core.xsd " +
				"    http://stix.mitre.org/Report-1 http://stix.mitre.org/XMLSchema/report/1.0/report.xsd " +
				"    http://stix.mitre.org/default_vocabularies-1 http://stix.mitre.org/XMLSchema/default_vocabularies/1.2.0/stix_default_vocabularies.xsd " +
				"    http://stix.mitre.org/common-1 http://stix.mitre.org/XMLSchema/common/1.2/stix_common.xsd " +
				"    http://data-marking.mitre.org/Marking-1 http://stix.mitre.org/XMLSchema/data_marking/1.2/data_marking.xsd " +
				"    http://cybox.mitre.org/cybox-2 http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd " +
				"    http://cybox.mitre.org/default_vocabularies-2 http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd " +
				"    http://stix.mitre.org/Indicator-2 http://stix.mitre.org/XMLSchema/indicator/2.2/indicator.xsd " +
				"    http://stix.mitre.org/TTP-1 http://stix.mitre.org/XMLSchema/ttp/1.2/ttp.xsd " +
				"    http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1 http://stix.mitre.org/XMLSchema/extensions/marking/terms_of_use/1.1/terms_of_use_marking.xsd " +
				"    http://cybox.mitre.org/objects#URIObject-2 http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd " +
				"    \"> " +
				"    <stix:STIX_Header--stix:Handling--marking:Marking--marking:Controlled_Structure> " +
				"        //node() | //@* " +
				"    </stix:STIX_Header--stix:Handling--marking:Marking--marking:Controlled_Structure> " +
				"    <stix:STIX_Header--stix:Handling--marking:Marking--marking:Marking_Structure--terms:Terms_Of_Use> " +
				"        APT1: Exposing One of China's Cyber Espionage Units (the \"APT1 Report\") is copyright 2013 by Mandiant Corporation and can be downloaded at intelreport.mandiant.com.  This XML file using the STIX standard was created by The MITRE Corporation using the content of the APT1 Report with Mandiant's permission.  Mandiant is not responsible for the content of this file. " +
				"    </stix:STIX_Header--stix:Handling--marking:Marking--marking:Marking_Structure--terms:Terms_Of_Use> " +
				"    <stix:STIX_Header--stix:Handling--marking:Marking--marking:Marking_Structure--xsi:type> " +
				"        terms:TermsOfUseMarkingStructureType " +
				"    </stix:STIX_Header--stix:Handling--marking:Marking--marking:Marking_Structure--xsi:type> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Identity--stixCommon:Name> " +
				"        MITRE " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Identity--stixCommon:Name> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Role> " +
				"        Transformer/Translator " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Role> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Role--xsi:type> " +
				"        stixVocabs:InformationSourceRoleVocab-1.0 " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Role--xsi:type> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Identity--stixCommon:Name> " +
				"        Mandiant " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Identity--stixCommon:Name> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Role> " +
				"        Initial Author " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Role> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Role--xsi:type> " +
				"        stixVocabs:InformationSourceRoleVocab-1.0 " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Role--xsi:type> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Time--cyboxCommon:Produced_Time> " +
				"        2013-02-19T00:00:00Z " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Time--cyboxCommon:Produced_Time> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Time--cyboxCommon:Produced_Time--precision> " +
				"        day " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Contributing_Sources--stixCommon:Source--stixCommon:Time--cyboxCommon:Produced_Time--precision> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Time--cyboxCommon:Produced_Time> " +
				"        2014-01-16T00:00:00Z " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Time--cyboxCommon:Produced_Time> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:Time--cyboxCommon:Produced_Time--precision> " +
				"        day " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:Time--cyboxCommon:Produced_Time--precision> " +
				"    <stix:STIX_Header--stix:Information_Source--stixCommon:References--stixCommon:Reference> " +
				"        http://intelreport.mandiant.com/Mandiant_APT1_Report.pdf " +
				"    </stix:STIX_Header--stix:Information_Source--stixCommon:References--stixCommon:Reference> " +
				"</stix:STIX_Package> ";
			
			//strip whitespace
			while(expectedNormalizedSTIXString.contains("> ")){
				expectedNormalizedSTIXString = expectedNormalizedSTIXString.replaceAll("> ", ">");
			}
			while(expectedNormalizedSTIXString.contains(" <")){
				expectedNormalizedSTIXString = expectedNormalizedSTIXString.replaceAll(" <", "<");
			}
			
			Document initialDoc = parseXMLText(STIXString);
			assertNotNull(initialDoc);
			System.out.println("initialDoc:\n" + XMLToString(initialDoc));
			
			Document normalizedDoc = flattenSTIX(initialDoc);
			assertNotNull(normalizedDoc);
			normalizedDoc = sortXML(normalizedDoc);
			System.out.println("normalizedDoc:\n" + XMLToString(normalizedDoc));
			
			Document expectedDoc = parseXMLText(expectedNormalizedSTIXString);
			assertNotNull(expectedDoc);
			expectedDoc = sortXML(expectedDoc);
			System.out.println("expectedDoc:\n" + XMLToString(expectedDoc));
			
			assertTrue(XMLToString(expectedDoc).equals(XMLToString(normalizedDoc)));
			
		} catch (Exception e) {
			e.printStackTrace();
			fail("Exception");
		}
	}
	
	
}
