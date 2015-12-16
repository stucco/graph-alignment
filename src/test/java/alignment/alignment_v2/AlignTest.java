package alignment.alignment_v2;

import org.junit.Test;
import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray;

import org.mitre.stix.stix_1.STIXPackage;

/**
 * Unit test for STIX Align
 */
public class AlignTest {

	@Test 
	public void tesCompare() throws Exception {

		System.out.println("In testCompare()");

		String vertOneString = 
			" { "+
			"      \"endIP\": \"216.98.188.255\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\\\"><cybox:Title>AddressRange<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:addressRange-3630349312-3630349567\\\"><cybox:Description>216.98.188.0 through 216.98.188.255<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" apply_condition=\\\"ANY\\\" condition=\\\"InclusiveBetween\\\" delimiter=\\\" - \\\">216.98.188.0 - 216.98.188.255<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AddressRange\","+
			"      \"startIP\": \"216.98.188.0\","+
			"      \"startIPInt\": \"3630349312\","+
			"      \"name\": \"216.98.188.0 - 216.98.188.255\","+
			"      \"description\": [\"216.98.188.0 through 216.98.188.255\"],"+
			"      \"source\": \"CAIDA\","+
			"      \"endIPInt\": \"3630349567\""+
			" }";

		String vertTwoString = 
			" {"+
			"      \"endIP\": \"216.98.179.255\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:addressRange-6f73e483-e897-430c-b09f-96219fe457ac\\\"><cybox:Title>AddressRange<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:addressRange-3630347008-3630347263\\\"><cybox:Description>216.98.179.0 through 216.98.179.255<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" apply_condition=\\\"ANY\\\" condition=\\\"InclusiveBetween\\\" delimiter=\\\" - \\\">216.98.179.0 - 216.98.179.255<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AddressRange\","+
			"      \"startIP\": \"216.98.179.0\","+
			"      \"startIPInt\": \"3630347008\","+
			"      \"name\": \"216.98.179.0 - 216.98.179.255\","+
			"      \"description\": [\"216.98.179.0 through 216.98.179.255\"],"+
			"      \"source\": \"CAIDA\","+
			"      \"endIPInt\": \"3630347263\""+
			" }";
		
		JSONObject vertOne = new JSONObject(vertOneString);
		JSONObject vertTwo = new JSONObject(vertTwoString);
		ConfigFileLoader config = new ConfigFileLoader();
		JSONObject vertexOntology = config.getVertexOntology("AddressRange");	
		Compare compare = new Compare();
	//	double score = compare.compareVertices(vertOne, vertOne, vertexOntology);
	//	double score = compare.compareVertices(vertOne, vertTwo, vertexOntology);
	}

	@Test 
	public void tesLoadDuplicateAS() throws Exception {

		System.out.println("In testLoad()");

		String graphString = 
			"{"+
			"  \"vertices\": {"+
			"    \"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\": {"+
			"      \"endIP\": \"216.98.188.255\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\\\"><cybox:Title>AddressRange<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:addressRange-3630349312-3630349567\\\"><cybox:Description>216.98.188.0 through 216.98.188.255<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" apply_condition=\\\"ANY\\\" condition=\\\"InclusiveBetween\\\" delimiter=\\\" - \\\">216.98.188.0 - 216.98.188.255<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AddressRange\","+
			"      \"startIP\": \"216.98.188.0\","+
			"      \"startIPInt\": \"3630349312\","+
			"      \"name\": \"216.98.188.0 - 216.98.188.255\","+
			"      \"description\": [\"216.98.188.0 through 216.98.188.255\"],"+
			"      \"source\": \"CAIDA\","+
			"      \"endIPInt\": \"3630349567\""+
			"    },"+
			"    \"stucco:as-7c852f47-dd54-4153-869e-e00b844fef38\": {"+
			"      \"number\": \"18548\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:as-7c852f47-dd54-4153-869e-e00b844fef38\\\"><cybox:Title>AS<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:as-18vo_18548\\\"><cybox:Description>AS 18VO has ASN 18548<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"ASObj:ASObjectType\\\"><ASObj:Number xmlns:ASObj=\\\"http://cybox.mitre.org/objects#ASObject-1\\\">18548<\\/ASObj:Number><ASObj:Name xmlns:ASObj=\\\"http://cybox.mitre.org/objects#ASObject-1\\\">18VO<\\/ASObj:Name><ASObj:Regional_Internet_Registry xmlns:ASObj=\\\"http://cybox.mitre.org/objects#ASObject-1\\\">ARIN<\\/ASObj:Regional_Internet_Registry><\\/cybox:Properties><cybox:Related_Objects><cybox:Related_Object idref=\\\"stucco:addressRange-6f73e483-e897-430c-b09f-96219fe457ac\\\"><cybox:Description>AS 18VO with ASN 18548 contains IP address range 216.98.179.0 through 216.98.179.255<\\/cybox:Description><cybox:Discovery_Method><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Discovery_Method><cybox:Relationship>Contains<\\/cybox:Relationship><\\/cybox:Related_Object><cybox:Related_Object idref=\\\"stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe\\\"><cybox:Description>AS 18VO with ASN 18548 contains IP address range 216.98.188.0 through 216.98.188.255<\\/cybox:Description><cybox:Discovery_Method><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Discovery_Method><cybox:Relationship>Contains<\\/cybox:Relationship><\\/cybox:Related_Object><\\/cybox:Related_Objects><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AS\","+
			"      \"name\": \"18VO\","+
			"      \"description\": [\"AS 18VO has ASN 18548\"],"+
			"      \"source\": \"CAIDA\""+
			"    },"+
			"    \"stucco:organization-8972a1d6-b59d-43de-83b8-851ee5871fcf\": {"+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:organization-8972a1d6-b59d-43de-83b8-851ee5871fcf\\\"><cybox:Title>Organization<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:organization-1_800_video_on__inc.\\\"><cybox:Description>Organization 1 800 Video On, Inc. located in US has a range of IP addresses<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"WhoisObj:WhoisObjectType\\\"><WhoisObj:Registrants xmlns:WhoisObj=\\\"http://cybox.mitre.org/objects#WhoisObject-2\\\"><WhoisObj:Registrant><WhoisObj:Address>US<\\/WhoisObj:Address><WhoisObj:Organization>1 800 Video On, Inc.<\\/WhoisObj:Organization><WhoisObj:Registrant_ID>18VO-ARIN<\\/WhoisObj:Registrant_ID><\\/WhoisObj:Registrant><\\/WhoisObj:Registrants><\\/cybox:Properties><cybox:Related_Objects><cybox:Related_Object idref=\\\"stucco:as-7c852f47-dd54-4153-869e-e00b844fef38\\\"><cybox:Description>Organization 1 800 Video On, Inc. has AS<\\/cybox:Description><cybox:Discovery_Method><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Discovery_Method><cybox:Relationship>Has_AS<\\/cybox:Relationship><\\/cybox:Related_Object><\\/cybox:Related_Objects><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"Organization\","+
			"      \"name\": \"1 800 Video On, Inc.\","+
			"      \"description\": [\"Organization 1 800 Video On, Inc. located in US has a range of IP addresses\"],"+
			"      \"source\": \"CAIDA\""+
			"    },"+
			"    \"stucco:addressRange-6f73e483-e897-430c-b09f-96219fe457ac\": {"+
			"      \"endIP\": \"216.98.179.255\","+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:addressRange-6f73e483-e897-430c-b09f-96219fe457ac\\\"><cybox:Title>AddressRange<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">CAIDA<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:addressRange-3630347008-3630347263\\\"><cybox:Description>216.98.179.0 through 216.98.179.255<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\" apply_condition=\\\"ANY\\\" condition=\\\"InclusiveBetween\\\" delimiter=\\\" - \\\">216.98.179.0 - 216.98.179.255<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"AddressRange\","+
			"      \"startIP\": \"216.98.179.0\","+
			"      \"startIPInt\": \"3630347008\","+
			"      \"name\": \"216.98.179.0 - 216.98.179.255\","+
			"      \"description\": [\"216.98.179.0 through 216.98.179.255\"],"+
			"      \"source\": \"CAIDA\","+
			"      \"endIPInt\": \"3630347263\""+
			"    }"+
			"  },"+
			"  \"edges\": ["+
			"    {"+
			"      \"inV\": \"216.98.179.0 - 216.98.179.255\","+
			"      \"label\": \"Contains\","+
			"      \"outV\": \"18VO\""+
			"    },"+
			"    {"+
			"      \"inV\": \"216.98.188.0 - 216.98.188.255\","+
			"      \"label\": \"Contains\","+
			"      \"outV\": \"18VO\""+
			"    },"+
			"    {"+
			"      \"inV\": \"18VO\","+
			"      \"label\": \"Has_AS\","+
			"      \"outV\": \"1 800 Video On, Inc.\""+
			"    }"+
			"  ]"+
			"}";

		JSONObject graph = new JSONObject(graphString);
		Align align = new Align();
		align.load(graph);
		JSONObject duplicateGraph = new JSONObject();
		JSONObject duplicateVertex = new JSONObject();
		duplicateVertex.put("stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe", 
			graph.getJSONObject("vertices").getJSONObject("stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe"));
		duplicateGraph.put("vertices", duplicateVertex);
		align.load(duplicateGraph);
		assertTrue(true);
	}
}
