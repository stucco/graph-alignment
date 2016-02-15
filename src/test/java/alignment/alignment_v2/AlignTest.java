package alignment.alignment_v2;

import alignment.alignment_v2.Constraint;
import alignment.alignment_v2.Constraint.Condition;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import org.junit.Test;
import static org.junit.Assert.*;

import org.json.JSONObject;
import org.json.JSONArray;

import org.mitre.stix.stix_1.STIXPackage;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;

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

	@Test 
	public void tesLoadASWithMultipleAddressRanges() throws Exception {

		System.out.println("[Running] alignment.alignment_v2.AlignTest.testLoadASWithMultipleAddressRanges()");

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
			"      \"inVertID\": \"216.98.179.0 - 216.98.179.255\","+
			"      \"relation\": \"Contains\","+
			"      \"outVertID\": \"18VO\""+
			"    },"+
			"    {"+
			"      \"inVertID\": \"216.98.188.0 - 216.98.188.255\","+
			"      \"relation\": \"Contains\","+
			"      \"outVertID\": \"18VO\""+
			"    },"+
			"    {"+
			"      \"inVertID\": \"18VO\","+
			"      \"relation\": \"Has_AS\","+
			"      \"outVertID\": \"1 800 Video On, Inc.\""+
			"    }"+
			"  ]"+
			"}";

		JSONObject graph = new JSONObject(graphString);
		Align align = new Align();
		align.load(graph);
		InMemoryDBConnectionJson db = align.getConnection();
		JSONObject vert = null;
		JSONObject originalVert = null;

	//	System.out.println("vertices = " + db.getVertCount());

		/* testing AddressRange */
		System.out.println("Testing AddressRange ...");
		vert = db.getVertByName("216.98.188.0 - 216.98.188.255");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		/* testing AddressRange */
		System.out.println("Testing AddressRange ... ");
		vert = db.getVertByName("216.98.179.0 - 216.98.179.255");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:addressRange-6f73e483-e897-430c-b09f-96219fe457ac");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		/* testing AS */
		System.out.println("Testing AS ... ");
		vert = db.getVertByName("18VO");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:as-7c852f47-dd54-4153-869e-e00b844fef38");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		/* testing Organization */
		System.out.println("Testing Organization");
		vert = db.getVertByName("1 800 Video On, Inc.");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:organization-8972a1d6-b59d-43de-83b8-851ee5871fcf");
		assertTrue(compareJSONObjects(vert, originalVert));

		String outVertID = null;
		String inVertID = null;
		List<String> edgeIDList = null;
		String edgeID = null;
		JSONObject edge = null;
		JSONObject originalEdge = null;

		/* testing Organization -> AS edge */
		System.out.println("Tesing Organization -> Has_AS -> AS edge");
		inVertID = db.getVertIDByName("18VO");
		outVertID = db.getVertIDByName("1 800 Video On, Inc.");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "Has_AS");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);	
		
		/* testing AS -> AddressRange edge */
		System.out.println("Testing AS -> Contains -> AddressRange edge");
		inVertID = db.getVertIDByName("216.98.179.0 - 216.98.179.255");
		outVertID = db.getVertIDByName("18VO");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "Contains");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);	
		
		/* testing AS -> AddressRange edge */
		System.out.println("Testing AS -> Contains -> AddressRange edge");
		inVertID = db.getVertIDByName("216.98.188.0 - 216.98.188.255");
		outVertID = db.getVertIDByName("18VO");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "Contains");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);
	}
	
	@Test
	public void testEdgeLoad() throws Exception {

		System.out.println("[Running] alignment.alignment_v2.AlignTest.testEdgeLoad()");

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
			"    \"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\": {"+
			"      \"sourceDocument\": \"<cybox:Observable xmlns:cybox=\\\"http://cybox.mitre.org/cybox-2\\\" id=\\\"stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241\\\"><cybox:Title>IP<\\/cybox:Title><cybox:Observable_Source><cyboxCommon:Information_Source_Type xmlns:cyboxCommon=\\\"http://cybox.mitre.org/common-2\\\">LoginEvent<\\/cyboxCommon:Information_Source_Type><\\/cybox:Observable_Source><cybox:Object id=\\\"stucco:ip-3232238091\\\"><cybox:Description>192.168.10.11<\\/cybox:Description><cybox:Properties xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" category=\\\"ipv4-addr\\\" xsi:type=\\\"AddressObj:AddressObjectType\\\"><AddressObj:Address_Value xmlns:AddressObj=\\\"http://cybox.mitre.org/objects#AddressObject-2\\\">216.98.188.1<\\/AddressObj:Address_Value><\\/cybox:Properties><\\/cybox:Object><\\/cybox:Observable>\","+
			"      \"vertexType\": \"IP\","+
			"      \"ipInt\": \"3630349313\","+
			"      \"name\": \"216.98.188.1\","+
			"      \"description\": \"216.98.188.1\","+
			"      \"source\": [\"LoginEvent\"]"+
			"    }" +
			"  }" +
			"}";
		
		JSONObject graph = new JSONObject(graphString);
		Align align = new Align();
		align.load(graph);
		InMemoryDBConnectionJson db = align.getConnection();
		JSONObject vert = null;
		JSONObject originalVert = null;

		/* testing AddressRange */
		System.out.println("Testing AddressRange ...");
		vert = db.getVertByName("216.98.188.0 - 216.98.188.255");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:addressRange-33f72b4c-e6f2-4d82-88d4-2a7711ce7bfe");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		/* testing IP */
		System.out.println("Testing AddressRange ... ");
		vert = db.getVertByName("216.98.188.1");
		assertNotNull(vert);
		originalVert = graph.getJSONObject("vertices").getJSONObject("stucco:ip-cf1042ad-8f95-47e2-830d-4951f81f5241");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		String outVertID = null;
		String inVertID = null;
		List<String> edgeIDList = null;
		String edgeID = null;
		JSONObject edge = null;
		JSONObject originalEdge = null;
		/* testing IP -> AddressRange edge */
		System.out.println("Testing IP -> Contained_Within -> AddressRange edge ...");
		inVertID = db.getVertIDByName("216.98.188.0 - 216.98.188.255");
		outVertID = db.getVertIDByName("216.98.188.1");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "Contained_Within");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);
	}

	@Test 
	public void testLoadDuplicate() throws Exception {

		System.out.println("[Running] alignment.alignment_v2.AlignTest.testLoadDuplicate()");

		String vertex =	
			"{"+
			"\"vertices\": {"+
			"  \"CVE-2015-2098\": {"+
			"    \"sourceDocument\": \"<stixCommon:Exploit_Target xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" id=\\\"stucco:vulnerability-95a58902-594d-4c46-8bb8-dca5834f6682\\\" xsi:type=\\\"et:ExploitTargetType\\\"><et:Title xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\">Vulnerability<\\/et:Title><et:Vulnerability xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\"><et:Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.<\\/et:Description><et:Short_Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities<\\/et:Short_Description><et:CVE_ID>CVE-2015-2098<\\/et:CVE_ID><et:OSVDB_ID>72838<\\/et:OSVDB_ID><et:Source>Bugtraq<\\/et:Source><et:Published_DateTime>2015-03-27T00:00:00.000-04:00<\\/et:Published_DateTime><et:References><stixCommon:Reference>http://support.microsoft.com/kb/240797<\\/stixCommon:Reference><stixCommon:Reference>Second<\\/stixCommon:Reference><stixCommon:Reference>Third<\\/stixCommon:Reference><\\/et:References><\\/et:Vulnerability><et:Potential_COAs xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\"><et:Potential_COA><stixCommon:Course_Of_Action idref=\\\"stucco:vulnerability-9d31d334-93f5-4819-ac1e-8ea8ce957cdf\\\" xsi:type=\\\"coa:CourseOfActionType\\\" /><\\/et:Potential_COA><\\/et:Potential_COAs><\\/stixCommon:Exploit_Target>\","+
			"    \"vertexType\": \"Vulnerability\","+
			"    \"name\": \"CVE-2015-2098\","+
			"    \"description\": [\"WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.\"],"+
			"    \"source\": [\"Bugtraq\"],"+
			"    \"publishedDate\": \"2015-03-27T00:00:00.000-04:00\","+
			"    \"shortDescription\": [\"WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities\"]"+
			"  }}}";

		String duplicate =	
			"{"+
			"\"vertices\": {"+
			"  \"CVE-nnnn-nnnn\": {"+
			"    \"sourceDocument\": \"<stixCommon:Exploit_Target xmlns:stixCommon=\\\"http://stix.mitre.org/common-1\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" id=\\\"stucco:vulnerability-95a58902-594d-4c46-8bb8-dca5834f6682\\\" xsi:type=\\\"et:ExploitTargetType\\\"><et:Title xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\">Vulnerability<\\/et:Title><et:Vulnerability xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\"><et:Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified.<\\/et:Description><et:Short_Description>WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities<\\/et:Short_Description><et:CVE_ID>CVE-nnnn-nnnn<\\/et:CVE_ID><et:OSVDB_ID>72838453<\\/et:OSVDB_ID><et:Source>NVD<\\/et:Source><et:Published_DateTime>2015-03-28T00:30:00.000-04:00<\\/et:Published_DateTime><et:References><stixCommon:Reference>http://support.microsoft.com/kb/240797<\\/stixCommon:Reference><stixCommon:Reference>Second<\\/stixCommon:Reference><stixCommon:Reference>Third<\\/stixCommon:Reference><\\/et:References><\\/et:Vulnerability><et:Potential_COAs xmlns:et=\\\"http://stix.mitre.org/ExploitTarget-1\\\"><et:Potential_COA><stixCommon:Course_Of_Action idref=\\\"stucco:vulnerability-9d31d334-93f5-4819-ac1e-8ea8ce957cdf\\\" xsi:type=\\\"coa:CourseOfActionType\\\" /><\\/et:Potential_COA><\\/et:Potential_COAs><\\/stixCommon:Exploit_Target>\","+
			"    \"vertexType\": \"Vulnerability\","+
			"    \"name\": \"CVE-nnnn-nnnn\","+
			"    \"description\": [\"WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities WebGate eDVR Manager is prone to multiple buffer-overflow vulnerabilities because it fails to perform boundary checks before copying user-supplied data to insufficiently sized memory buffer. The controls are identified by CLSID's: 359742AF-BF34-4379-A084-B7BF0E5F34B0 4E14C449-A61A-4BF7-8082-65A91298A6D8 5A216ADB-3009-4211-AB77-F1857A99482C An attacker can exploit these issues to execute arbitrary code in the context of the application, usually Internet Explorer, using the ActiveX control.Failed attacks will likely cause denial-of-service conditions.\"],"+
			"    \"source\": [\"NVD\"],"+
			"    \"publishedDate\": \"2015-03-27T00:00:00.000-04:00\","+
			"    \"shortDescription\": [\"WebGate eDVR Manager ActiveX Controls CVE-2015-2098 Multiple Buffer Overflow Vulnerabilities\"]"+
			"  }"+
			"}}";

		Align align = new Align();
		align.setSearchForDuplicates(true);
		align.setAlignVertProps(true);
		InMemoryDBConnectionJson db = align.getConnection();
		align.load(new JSONObject(vertex));
		
		JSONObject vert = db.getVertByName("CVE-2015-2098");
		JSONObject originalVert = new JSONObject(vertex).getJSONObject("vertices").getJSONObject("CVE-2015-2098");
		assertTrue(compareJSONObjects(vert, originalVert));

		align.load(new JSONObject(duplicate));
		vert = db.getVertByName("CVE-nnnn-nnnn");
		assertNull(vert);
	}
		
	@Test
	public void testLoadIndicatorDuplicateTest() throws Exception {
		
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
			"      \"name\": \"Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb\""+
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
			"      \"name\": \"Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402\""+
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

		Align align = new Align();
		align.setSearchForDuplicates(true);
		align.setAlignVertProps(true);
		InMemoryDBConnectionJson db = align.getConnection();
		align.load(new JSONObject(graphSectionOne));
		
		System.out.println("Testing TTP ...");
		JSONObject vert = db.getVertByName("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
		JSONObject originalVert = new JSONObject(graphSectionOne).getJSONObject("vertices").getJSONObject("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		System.out.println("Testing Course_Of_Action ...");
		vert = db.getVertByName("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
		originalVert = new JSONObject(graphSectionOne).getJSONObject("vertices").getJSONObject("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
		assertTrue(compareJSONObjects(vert, originalVert));

		System.out.println("Testing Indicator ...");
		vert = db.getVertByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
		originalVert = new JSONObject(graphSectionOne).getJSONObject("vertices").getJSONObject("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
		assertTrue(compareJSONObjects(vert, originalVert));
		
		String outVertID = null;
		String inVertID = null;
		List<String> edgeIDList = null;
		String edgeID = null;
		JSONObject edge = null;
		System.out.println("Testing Indicator -> IndicatedTTP -> TTP edge ...");

		inVertID = db.getVertIDByName("TTP-c7561b63-ab62-433e-a5c2-b330c1dcc341");
		outVertID = db.getVertIDByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "IndicatedTTP");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);	
		
		System.out.println("Testing Indicator -> SuggestedCOA -> Course_Of_Action edge ...");
		inVertID = db.getVertIDByName("Course_Of_Action-ae6c9867-9433-481c-80e5-4672d92811bb");
		outVertID = db.getVertIDByName("Indicator-c304f71f-788d-46cb-919d-da1ca4c781bb");
		edgeIDList = db.getEdgeIDsByVert(inVertID, outVertID, "SuggestedCOA");
		assertTrue(edgeIDList.size() == 1);
		edgeID = edgeIDList.get(0);	
		edge = db.getEdgeByID(edgeID);
		assertNotNull(edge);
		
		align.load(new JSONObject(graphSectionTwo));
		System.out.println("Testing Indicator duplicate ...");
		vert = db.getVertByName("Indicator-a32549e9-02ea-4891-8f4d-e3b0412ac402");
		assertNull(vert);	
		
		align.load(new JSONObject(graphSectionTwo));
		System.out.println("Testing TTP duplicate ...");
		vert = db.getVertByName("TTP-e94f0d8c-8f73-41a6-a834-9bcada3d3c70");
		assertNull(vert);	
	}
	
//	@Test
	public void testLoadNestedIndicatorsTest() throws Exception {
		
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
			"      \"name\": \"Indicator-8cb410ca-6cd5-4e64-a49a-28798837025b\""+
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
		
		Align align = new Align();
		align.setSearchForDuplicates(true);
		align.setAlignVertProps(true);
		InMemoryDBConnectionJson db = align.getConnection();
		align.load(new JSONObject(graphSectionOne));
		align.load(new JSONObject(graphSectionTwo));
		
		List<Constraint> constraints1 = new ArrayList<Constraint>();
		constraints1.add(new Constraint("vertexType", Condition.eq, "Indicator"));
		List<String> indicatorList = db.getVertIDsByConstraints(constraints1);
		assertTrue(indicatorList.size() == 1);

		List<Constraint> constraints2 = new ArrayList<Constraint>();
		constraints2.add(new Constraint("vertexType", Condition.eq, "TTP"));
		List<String> ttpList = db.getVertIDsByConstraints(constraints2);
		assertTrue(ttpList.size() == 1);

		List<Constraint> constraints3 = new ArrayList<Constraint>();
		constraints3.add(new Constraint("vertexType", Condition.eq, "Course_Of_Action"));
		List<String> coaList = db.getVertIDsByConstraints(constraints3);
		assertTrue(coaList.size() == 1);
		String indicatorName = db.getVertByID(indicatorList.get(0)).getString("name");
		List<String> indicatedTTP = db.getInVertIDsByRelation(indicatorName, "IndicatedTTP");
		assertTrue(indicatedTTP.size() == 1);
		List<String> suggestedCOA = db.getInVertIDsByRelation(indicatorName, "SuggestedCOA");
		assertTrue(suggestedCOA.size() == 1);
	}
}
