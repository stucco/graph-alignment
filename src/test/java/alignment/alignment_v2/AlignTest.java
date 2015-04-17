package alignment.alignment_v2;

import gov.ornl.stucco.DBClient.DBConnection;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AlignTest 
extends TestCase
{
	private static final int WAIT_TIME = 3;

	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public AlignTest( String testName )
	{
		super( testName );
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite()
	{
		return new TestSuite( AlignTest.class );
	}


	/**
	 * Add a duplicate vertex, from a different source, with similar but non-identical properties.
	 * See if the Align class can identify that they should be matched.
	 */
	public void testLoadDuplicate()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();

		String test_graphson_verts = "{\"vertices\":[" +
				"{" +
				"\"_id\":\"CVE-1999-0002\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"CVE\","+
				"\"vertexType\": \"vulnerability\"," +
				"\"description\":\"Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.\","+
				"\"references\":["+
				"\"CERT:CA-98.12.mountd\","+
				"\"http://www.ciac.org/ciac/bulletins/j-006.shtml\","+
				"\"http://www.securityfocus.com/bid/121\","+
				"\"XF:linux-mountd-bo\"],"+
				"\"status\":\"Entry\","+
				"\"score\":1.0"+
				"}," + 
				"{" +
				"\"availabilityImpact\": \"PARTIAL\"," +
				"\"accessVector\": \"NETWORK\"," +
				"\"cvssDate\": 1072933200," +
				"\"integrityImpact\": \"NONE\"," +
				"\"vulnerableSoftware\": [\"cpe:/h:cabletron:smartswitch_router_8000_firmware:2.0\"]," +
				"\"accessComplexity\": \"LOW\"," +
				"\"modifiedDate\": 1220587200," +
				"\"vertexType\": \"vulnerability\"," +
				"\"_type\": \"vertex\"," +
				"\"references\":   [" +
				"\"http://razor.bindview.com/publish/advisories/adv_Cabletron.html\"," +
				"\"http://www.securityfocus.com/bid/841\"]," +
				"\"_id\": \"CVE-1999-1548\"," +
				"\"source\": \"NVD\"," +
				"\"description\": \"Cabletron SmartSwitch Router (SSR) 8000 firmware 2.x can only handle 200 ARP requests per second allowing a denial of service attack to succeed with a flood of ARP requests exceeding that limit.\"," +
				"\"cvssScore\": 5," +
				"\"publishedDate\": 943419600," +
				"\"confidentialityImpact\": \"NONE\"," +
				"\"accessAuthentication\": \"NONE\"" +
				"}," +	
				"{\"_id\":\"CVE-1999-nnnn\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"CVE\","+
				"\"vertexType\": \"vulnerability\"," +
				"\"description\":\"test description asdf.\","+
				"\"references\":[\"http://www.google.com\"],"+
				"\"status\":\"Entry\","+
				"\"score\":1.0"+
				"}],"+
				"\"edges\":[{"+ 
				"\"_id\":\"asdf\"," +
				"\"_inV\":\"CVE-1999-0002\"," +
				"\"_outV\":\"CVE-1999-nnnn\"," +
				"\"_label\":\"some_label_asdf\","+
				"\"some_property\":\"some_value\""+
				"}," +
				"{" +
				"\"_id\":\"asdfAgain\"," +
				"\"_inV\":\"CVE-1999-0002\"," +
				"\"_outV\":\"CVE-1999-1548\"," +
				"\"_label\":\"some_label_asdfAgain\","+
				"\"some_property\":\"some_valueAgain\""+
				"}]}";

		a.load(test_graphson_verts);

		Map<String, Object> vertProps = new HashMap<String, Object>();

		vertProps.put("accessVector", "NETWORK");
		//vertProps.put("accessVector", "Remote");
		vertProps.put("Credit", "Publicized in a Bindview Security Advisory released November 24,1999. Contact is Scott Blake <blake@bos.bindview.com>.");
		vertProps.put("name", "bugtraq_821");
		//vertMap.put("_id", "CVE-1999-1548");
		vertProps.put("solution", "Solution:Firmware revisions 3.x are not vulnerable to this attack. The latest firmware can be obtained at:http://www.cabletron.com/download/download.cgi?lib=ssr");
		vertProps.put("exploit", "see discussion");
		vertProps.put("modifiedDate", 1247284800);
		//vertProps.put("modifiedDate", "asdf");
		vertProps.put("vertexType", "vulnerability");
		ArrayList<String> l = new ArrayList<String>();
		l.add("http://razor.bindview.com/publish/advisories/adv_Cabletron.html");
		vertProps.put("references", l);
		vertProps.put("source", "bugtraq");
		vertProps.put("shortDescription", "Cabletron SSR ARP Flood DoS Vulnerability");
		vertProps.put("description", "The Cabletron SmartSwitch Router 8000 with firmware revision 2.x has been shown to susceptible to a denial of service attack. The SSR can only handle approximately 200 ARP requests per second. If an attacker can get ICMP traffic to the router, they can flood it with ARP requests, effectively shutting the router down for the duration of the attack.");
		l = new ArrayList<String>();
		l.add("Cabletron SmartSwitch Router 8000 2.0");
		vertProps.put("Vulnerable", l);
		vertProps.put("Not_Vulnerable", new ArrayList<String>());
		vertProps.put("publishedDate", "943401600");

		Map<String, Object> vertMap = new HashMap<String, Object>();
		vertMap.put("_properties", vertProps);
		vertMap.put("_type", "vertex");
		//vertMap.put("_id", null);


		String bestID = a.findDuplicateVertex(vertMap);
		assertNotNull(bestID);
		Map<String, Object> foundVert = c.getVertByID(bestID);
		//Map<String, Object> foundVertProps = (Map<String, Object>)foundVert.get("_properties");
		assertEquals("CVE-1999-1548", (String)foundVert.get("name"));

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	public void testIPRangeHandling()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();

		String test_graphson_verts = "{\"vertices\":[" +
				"{\"_id\":\"69.42.215.170\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"IP\"," +
				"\"ipInt\":1160435626" +
				"}," +
				"{\"_id\":\"9.42.215.170\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"IP\"," +
				"\"ipInt\":153802666" +
				"}," +
				"{\"_id\":\"169.42.215.170\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"IP\"," +
				"\"ipInt\":2838157226" +
				"}," +
				"]}";

		a.load(test_graphson_verts);

		test_graphson_verts = "{\"vertices\":[" +
				"{\"_id\":\"69.42.192.0_through_69.43.159.255\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"addressRange\"," +
				"\"startIP\":\"69.42.192.0\"," +
				"\"endIP\":\"69.43.159.255\"," +
				"\"startIPInt\":1160429568," +
				"\"endIPInt\":1160486911" +
				"}," + 
				"]}";

		a.load(test_graphson_verts);

		String outv_id = c.findVertId("69.42.215.170");
		String inv_id = c.findVertId("69.42.192.0_through_69.43.159.255");
		assertTrue(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		outv_id = c.findVertId("9.42.215.170");
		assertFalse(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		outv_id = c.findVertId("169.42.215.170");
		assertFalse(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		test_graphson_verts = "{\"vertices\":[" +
				"{\"_id\":\"169.42.192.0_through_169.43.159.255\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"addressRange\"," +
				"\"startIP\":\"169.42.192.0\"," +
				"\"endIP\":\"169.43.159.255\"," +
				"\"startIPInt\":2838151168," +
				"\"endIPInt\":2838208511" +
				"}," +
				"]}";

		a.load(test_graphson_verts);

		outv_id = c.findVertId("169.42.215.170");
		inv_id = c.findVertId("169.42.192.0_through_169.43.159.255");
		//System.out.println("in: " + inv_id + " out: " + outv_id);
		assertTrue(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		outv_id = c.findVertId("69.42.215.170");
		assertFalse(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		outv_id = c.findVertId("9.42.215.170");
		assertFalse(c.edgeExists(inv_id, outv_id, "inAddressRange"));


		test_graphson_verts = "{\"vertices\":[" +
				"{\"_id\":\"69.42.215.171\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"IP\"," +
				"\"ipInt\":1160435627" +
				"}" + 
				"]}";

		a.load(test_graphson_verts);

		outv_id = c.findVertId("69.42.215.171");
		inv_id = c.findVertId("69.42.192.0_through_69.43.159.255");
		assertTrue(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		inv_id = c.findVertId("169.42.192.0_through_169.43.159.255");
		assertFalse(c.edgeExists(inv_id, outv_id, "inAddressRange"));

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	public void testJsonVertToMap()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		String test_graphson_vert = "{" +
				"\"_id\":\"69.42.215.170\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"test\","+
				"\"vertexType\": \"IP\"," +
				"\"ipInt\":1160435626" +
				"}";

		JSONObject vertJSON = new JSONObject(test_graphson_vert);
		Map<String, Object> vertMap = a.jsonVertToMap( vertJSON );

		assertEquals(vertJSON.get("vertexType"), vertMap.get("vertexType"));
		assertEquals(vertJSON.get("ipInt"), vertMap.get("ipInt"));
		assertEquals(vertJSON.get("source"), vertMap.get("source"));

		test_graphson_vert = "{" +
				"\"availabilityImpact\": \"PARTIAL\"," +
				"\"accessVector\": \"NETWORK\"," +
				"\"cvssDate\": 1072933200," +
				"\"integrityImpact\": \"NONE\"," +
				"\"vulnerableSoftware\": [\"cpe:/h:cabletron:smartswitch_router_8000_firmware:2.0\"]," +
				"\"accessComplexity\": \"LOW\"," +
				"\"modifiedDate\": 1220587200," +
				"\"vertexType\": \"vulnerability\"," +
				"\"_type\": \"vertex\"," +
				"\"references\":   [" +
				"\"http://razor.bindview.com/publish/advisories/adv_Cabletron.html\"," +
				"\"http://www.securityfocus.com/bid/841\"]," +
				"\"_id\": \"CVE-1999-1548\"," +
				"\"source\": \"NVD\"," +
				"\"description\": \"Cabletron SmartSwitch Router (SSR) 8000 firmware 2.x can only handle 200 ARP requests per second allowing a denial of service attack to succeed with a flood of ARP requests exceeding that limit.\"," +
				"\"cvssScore\": 5," +
				"\"publishedDate\": 943419600," +
				"\"confidentialityImpact\": \"NONE\"," +
				"\"accessAuthentication\": \"NONE\"" +
				"}";

		vertJSON = new JSONObject(test_graphson_vert);
		vertMap = a.jsonVertToMap( vertJSON );

		assertEquals(vertJSON.get("availabilityImpact"), vertMap.get("availabilityImpact"));
		assertEquals(vertJSON.get("accessVector"), vertMap.get("accessVector"));
		assertEquals(vertJSON.get("cvssDate"), vertMap.get("cvssDate"));
		assertEquals(vertJSON.get("integrityImpact"), vertMap.get("integrityImpact"));
		assertTrue(a.jsonArrayToList((JSONArray)vertJSON.get("vulnerableSoftware")).equals(vertMap.get("vulnerableSoftware")));
		assertEquals(vertJSON.get("accessComplexity"), vertMap.get("accessComplexity"));
		assertEquals(vertJSON.get("modifiedDate"), vertMap.get("modifiedDate"));
		assertEquals(vertJSON.get("vertexType"), vertMap.get("vertexType"));
		assertTrue(a.jsonArrayToList((JSONArray)vertJSON.get("references")).equals(vertMap.get("references")));
		assertEquals(vertJSON.get("source"), vertMap.get("source"));
		assertEquals(vertJSON.get("description"), vertMap.get("description"));
		assertEquals(vertJSON.get("cvssScore"), vertMap.get("cvssScore"));
		assertEquals(vertJSON.get("publishedDate"), vertMap.get("publishedDate"));
		assertEquals(vertJSON.get("confidentialityImpact"), vertMap.get("confidentialityImpact"));
		assertEquals(vertJSON.get("accessAuthentication"), vertMap.get("accessAuthentication"));
	}

	public void testGetIpInt()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		String ip = "69.42.215.170";

		long ipInt = a.getIpInt(ip);

		assertEquals(Long.parseLong("1160435626"), ipInt);
	}

	/**
	 * Test AlignVertProps method with different merge methods
	 */
	public void testAlignVertPropsMergeMethods()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		Map<String, Object> props = new HashMap<String,Object>();
		props.put("NAME", "testvert_align_props");
		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"startTime\",55);v.setProperty(\"name\",NAME)", props);
		//c.execute("v = g.addVertex();v.setProperty(\"startTime\",55);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, Map<String, Object>> mergeMethods = new HashMap<String, Map<String, Object>>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//update a prop (appendList) (always updates) (list/list case)
		Map<String, Object> propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepNew");
		mergeMethods.put("references", propEntry);
		String[] testArrayVal = {"aaa", "bbb"};
		newProps.put("references", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		String[] testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "appendList");
		mergeMethods.put("references", propEntry);
		testArrayVal = new String[]{"ccc"};
		newProps.put("references", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (list/val case)
		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepNew");
		mergeMethods.put("references", propEntry);
		testArrayVal = new String[]{"aaa", "bbb"};
		newProps.put("references", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "appendList");
		mergeMethods.put("references", propEntry);
		testVal = "ccc";
		newProps.put("references", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (val/list case)
		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepNew");
		mergeMethods.put("references", propEntry);
		testVal = "aaa";
		newProps.put("references", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("references");
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "appendList");
		mergeMethods.put("references", propEntry);
		testArrayVal = new String[]{"bbb", "ccc"};
		newProps.put("references", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (val/val case)
		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepNew");
		mergeMethods.put("references", propEntry);
		testVal = "aaa";
		newProps.put("references", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("references");
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "appendList");
		mergeMethods.put("references", propEntry);
		testVal = "bbb";
		newProps.put("references", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("references")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}


	/**
	 * Testing the keepNew option for AlignVertProps
	 */

	public void testAlignVertPropsKeepNew()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"startTime\",55);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, Map<String, Object>> mergeMethods = new HashMap<String, Map<String, Object>>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("state", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		assertEquals(testVal, testProp);

		//update a prop (keepNew) (always updates)
		Map<String, Object> propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepNew");
		mergeMethods.put("state", propEntry);
		testVal = "bbbb";
		newProps.put("state", testVal);

		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		assertEquals(testVal, testProp);

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	/**
	 * Testing the appendList option for AlignVertProps
	 */

	public void testAlignVertPropsAppendList()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		String testVertex = "v = g.addVertex();" + 
				"v.setProperty(\"name\",\"CVE-1999-0006\");" + 
				"v.setProperty(\"cvssDate\", \"1500\");" + 
				"v.addProperty(\"references\", \"http://www.securityfocus.com/bid/133\");" +
				"v.setProperty(\"_type\", \"vertex\");" +
				"v.setProperty(\"availabilityImpact\", \"COMPLETE\");" +
				"v.setProperty(\"description\", \"Buffer overflow in POP servers based on BSD/Qualcomm's qpopper allows remote attackers to gain root access using a long PASS command.\");" +
				"v.addProperty(\"source\", \"NVD\");" + 
				//"v.setProperty(\"vulnerableSoftware\", \"cpe:/a:qualcomm:qpopper:2.4\");" + 
				"v.setProperty(\"vertexType\", \"vulnerability\");" + 
				"v.setProperty(\"accessComplexity\", \"LOW\");" + 
				"v.setProperty(\"confidentialityImpact\", \"COMPLETE\");" + 
				"v.setProperty(\"cvssScore\", 10);" +
				"v.setProperty(\"accessAuthentication\", \"NONE\");" +
				"v.setProperty(\"modifiedDate\", \"1000\");" +
				"v.setProperty(\"integrityImpact\", \"COMPLETE\");" +
				"v.setProperty(\"_id\", \"CVE-1999-0006\");" +
				"v.setProperty(\"publishedDate\", \"2000\");" +
				"v.setProperty(\"accessVector\", \"NETWORK\")";

		c.commit();
		c.execute(testVertex);
		c.commit();

		String id = c.findVertId("CVE-1999-0006");
		Map<String, Map<String, Object>> mergeMethods = new HashMap<String, Map<String, Object>>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
		a.alignVertProps(id, newProps, mergeMethods);	//id, new properties and how to merge 

		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		Map<String, Object> propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "appendList");
		mergeMethods.put("testprop", propEntry);
		testVal = "bbbb";
		newProps.put("testprop", testVal);

		a.alignVertProps(id, newProps, mergeMethods);
		ArrayList<String> testList = (ArrayList<String>)c.getVertByID(id).get("testprop");
		ArrayList<String> expectedList = new ArrayList<String>();
		expectedList.add("aaaa");
		expectedList.add("bbbb");
		assertEquals(expectedList, testList);

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	/**
	 * Testing the keepUpdates option for AlignVertProps
	 */
	public void testAlignVertPropsKeepUpdates()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, Map<String, Object>> mergeMethods = new HashMap<String, Map<String, Object>>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("state", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		assertEquals(testVal, testProp);

		//update a prop (keepUpdates) (update case)
		Map<String, Object> propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepUpdates");
		mergeMethods.put("state", propEntry);
		testVal = "bbbb";
		newProps.put("state", testVal);
		newProps.put("timestamp", 1001L);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		assertEquals(testVal, testProp);

		//update a prop (keepUpdates) (no update case)
		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepUpdates");
		mergeMethods.put("state", propEntry);
		testVal = "cccc";
		newProps.put("state", testVal);
		newProps.put("timestamp", 999L);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		testVal = "bbbb";
		assertEquals(testVal, testProp);

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	/**
	 * Testing the keepConfidence option for AlignVertProps
	 */
	public void testAlignVertPropsKeepConfidence()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, Map<String, Object>> mergeMethods = new HashMap<String, Map<String, Object>>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("state", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("state");
		assertEquals(testVal, testProp);

		//update a prop (keepConfidence) (update case)
		Map<String, Object> propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepConfidence");
		mergeMethods.put("state", propEntry);

		//update a prop (keepConfidence) (no update case)
		propEntry = new HashMap<String, Object>();
		propEntry.put("resolutionFunction", "keepConfidence");
		mergeMethods.put("state", propEntry);

		//TODO: this test seems unfinished??

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	/**
	 * Testing merging of various properties from schema/config
	 */
	/*
	//old method, now uses a config file.  may revisit.
	public void testMergeMethodsFromSchema()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		String ontologyStrTest = "{"+
				"  \"description\":\"The top level of the graph\","+
				"  \"type\":\"object\","+
				"  \"$schema\": \"http://json-schema.org/draft-03/schema\","+
				"  \"id\": \"gov.ornl.sava.stucco/graph\","+
				"  \"required\":false,"+
				"  \"properties\":{"+
				"    \"mode\": {"+
				"      \"type\": \"gov.ornl.sava.graphson.normal/graph/mode\""+
				"    },"+
				"    \"edges\": {"+
				"      \"title\":\"edges\","+
				"      \"description\":\"The list of edges in this graph\","+
				"      \"type\":\"array\","+
				"      \"id\": \"gov.ornl.sava.stucco/graph/edges\","+
				"      \"required\":false,"+
				"      \"items\":[ "+
				"        {"+
				"          \"id\": \"gov.ornl.sava.stucco/graph/edges/logsInTo\","+
				"          \"extends\": \"gov.ornl.sava.graphson.normal/graph/edges/base\","+
				"          \"title\":\"logsInTo\","+
				"          \"description\":\"'account' -'logsInTo'-> 'host'\","+
				"          \"properties\":{"+
				"            \"inVType\":{"+
				"              \"required\":true,"+
				"              \"enum\":[\"host\"]"+
				"            },"+
				"            \"outVType\":{"+
				"              \"required\":true,"+
				"              \"enum\":[\"account\"]"+
				"            }"+
				"          }"+
				"        }"+
				"      ]"+
				"    },"+
				"    \"vertices\": {"+
				"      \"title\":\"vertices\","+
				"      \"description\":\"The list of vertices in this graph\","+
				"      \"type\":\"array\","+
				"      \"id\": \"gov.ornl.sava.stucco/graph/vertices\","+
				"      \"required\":false,"+
				"      \"items\":["+
				"        {"+
				"          \"id\": \"gov.ornl.sava.stucco/graph/vertices/software\","+
				"          \"extends\": \"gov.ornl.sava.graphson.normal/graph/vertices/base\","+
				"          \"title\":\"software\","+
				"          \"description\":\"Any software components on a system, including OSes, applications, services, and libraries.\","+
				"          \"properties\":{"+
				"            \"vertexType\":{"+
				"              \"required\":true,"+
				"              \"enum\":[\"software\"]"+
				"            },"+
				//merge fields here are all arbitrary, will not match the real ontology...
				"            \"source\":{"+
				"              \"merge\":\"timestamp\","+
				"              \"required\":false"+
				"            },"+
				"            \"description\":{"+
				"              \"merge\":\"keepNew\","+
				"              \"required\":false"+
				"            },"+
				"            \"modifiedDate\":{"+
				"              \"merge\":\"keepUpdates\","+
				"              \"required\":false"+
				"            },"+
				"            \"vendor\":{"+
				"              \"merge\":\"timestamp\","+
				"              \"required\":false"+
				"            },"+
				"            \"product\":{"+
				"              \"merge\":\"appendList\","+
				"              \"required\":false"+
				"            },"+
				"            \"version\":{"+
				//"              \"merge\":\"keepNew\","+
				"              \"required\":false"+
				"            }"+
				"          }"+
				"        }"+
				"      ]"+
				"    }"+
				"  }"+
				"}";

		JSONObject ontology = new JSONObject(ontologyStrTest);
		Map<String, Map<String,String>> mergeMethods = Align.mergeMethodsFromSchema(ontology);
		assertEquals("timestamp", mergeMethods.get("software").get("source"));
		assertEquals("keepNew", mergeMethods.get("software").get("description"));
		assertEquals("keepUpdates", mergeMethods.get("software").get("modifiedDate"));
		assertEquals("timestamp", mergeMethods.get("software").get("vendor"));
		assertEquals("appendList", mergeMethods.get("software").get("product"));
		assertEquals("keepNew", mergeMethods.get("software").get("version"));

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}*/

	/**
	 * Tests loading & querying from realistic graphson file (~2M file)
	 * @throws IOException 
	 */
	/*
	public void testGraphsonFile() throws IOException
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig(), WAIT_TIME);
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		String test_graphson_verts = org.apache.commons.io.FileUtils.readFileToString(new File("resources/metasploit_short.json"), "UTF8");
		a.load(test_graphson_verts);

		try {
			//find this node, check some properties.
			String id = c.findVertId("CVE-2006-3459");
			Map<String, Object> query_ret_map = c.getVertByID(id);
			assertEquals("Metasploit", query_ret_map.get("source"));
			assertEquals("vulnerability", query_ret_map.get("vertexType"));

			//find this other node, check its properties.
			String id2 = c.findVertId("exploit/apple_ios/email/mobilemail_libtiff");
			query_ret_map = c.getVertByID(id2);
			assertEquals("Metasploit", query_ret_map.get("source"));
			assertEquals("malware", query_ret_map.get("vertexType"));
			assertEquals("exploit", query_ret_map.get("malwareType"));
			assertEquals("2006-08-01 00:00:00", query_ret_map.get("discoveryDate"));
			assertEquals("Apple iOS MobileMail LibTIFF Buffer Overflow", query_ret_map.get("shortDescription"));
			assertEquals("This module exploits a buffer overflow in the version of libtiff shipped with firmware versions 1.00, 1.01, 1.02, and 1.1.1 of the Apple iPhone. iPhones which have not had the BSD tools installed will need to use a special payload.", query_ret_map.get("fullDescription"));

			//and now test the edge between them
			Object query_ret;
			query_ret = c.getClient().execute("g.v("+id2+").outE().inV();");
			List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
			query_ret_map = query_ret_list.get(0);
			assertEquals(id, query_ret_map.get("_id"));

			c.removeAllVertices();
			//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it

		} catch (RexProException e) {
			fail("RexProException");
			e.printStackTrace();
		} catch (IOException e) {
			fail("IOException");
			e.printStackTrace();
		}
	}
	 */

	/*
	public void testAddNodeFile() throws IOException
	{
		Align a = new Align();

		String test_graphson_verts_one = org.apache.commons.io.FileUtils.readFileToString(new File("resources/NVD.json"), "UTF8");
		String test_graphson_verts_two = org.apache.commons.io.FileUtils.readFileToString(new File("resources/bugtraq.json"), "UTF8");

		a.load(test_graphson_verts_one);

		AddNode an = new AddNode(a);
		an.findDuplicateVertex(test_graphson_verts_two);

		a.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}
	 */
}


