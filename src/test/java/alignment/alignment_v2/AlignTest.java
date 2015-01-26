package alignment.alignment_v2;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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


	//refactoring broke this, will re-add soon.
	public void testLoadDuplicate()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();

		String test_graphson_verts = "{\"vertices\":[" +
				"{" +
				"\"_id\":\"CVE-1999-0002\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"CVE\","+
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
				"\"cvssDate\": \"2004-01-01T00:00:00.000-05:00\"," +
				"\"integrityImpact\": \"NONE\"," +
				"\"vulnerableSoftware\": [\"cpe:/h:cabletron:smartswitch_router_8000_firmware:2.0\"]," +
				"\"accessComplexity\": \"LOW\"," +
				"\"modifiedDate\": \"2008-09-05T16:19:47.303-04:00\"," +
				"\"vertexType\": \"vulnerability\"," +
				"\"_type\": \"vertex\"," +
				"\"references\":   [" +
				"\"http://razor.bindview.com/publish/advisories/adv_Cabletron.html\"," +
				"\"http://www.securityfocus.com/bid/841\"]," +
				"\"_id\": \"CVE-1999-1548\"," +
				"\"source\": \"NVD\"," +
				"\"description\": \"Cabletron SmartSwitch Router (SSR) 8000 firmware 2.x can only handle 200 ARP requests per second allowing a denial of service attack to succeed with a flood of ARP requests exceeding that limit.\"," +
				"\"cvssScore\": 5," +
				"\"publishedDate\": \"1999-11-24T00:00:00.000-05:00\"," +
				"\"confidentialityImpact\": \"NONE\"," +
				"\"accessAuthentication\": \"NONE\"" +
				"}," +	
				"{\"_id\":\"CVE-1999-nnnn\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"CVE\","+
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
		
		vertProps.put("accessVector", "Remote");
		vertProps.put("Credit", "Publicized in a Bindview Security Advisory released November 24,1999. Contact is Scott Blake <blake@bos.bindview.com>.");
		vertProps.put("name", "bugtraq_821");
		//vertMap.put("_id", "CVE-1999-1548");
		vertProps.put("solution", "Solution:Firmware revisions 3.x are not vulnerable to this attack. The latest firmware can be obtained at:http://www.cabletron.com/download/download.cgi?lib=ssr");
		vertProps.put("exploit", "see discussion");
		vertProps.put("modifiedDate", "Jul 11 2009 12:56AM");
		vertProps.put("vertexType", "vulnerability");
		vertProps.put("references", new ArrayList<String>());
		vertProps.put("source", "bugtraq");
		vertProps.put("shortDescription", "Cabletron SSR ARP Flood DoS Vulnerability");
		vertProps.put("description", "The Cabletron SmartSwitch Router 8000 with firmware revision 2.x has been shown to susceptible to a denial of service attack. The SSR can only handle approximately 200 ARP requests per second. If an attacker can get ICMP traffic to the router, they can flood it with ARP requests, effectively shutting the router down for the duration of the attack.");
		ArrayList<String> l = new ArrayList<String>();
		l.add("Cabletron SmartSwitch Router 8000 2.0");
		vertProps.put("Vulnerable", l);
		vertProps.put("Not_Vulnerable", new ArrayList<String>());
		vertProps.put("publishedDate", "Nov 24 1999 12:00AM");
		
		Map<String, Object> vertMap = new HashMap<String, Object>();
		vertMap.put("_properties", vertProps);
		vertMap.put("_type", "vertex");
		//vertMap.put("_id", null);
		
		
		String bestID = a.findDuplicateVertex(vertMap);
		//System.out.println("best match was: " + bestID);
		//TODO verify

		c.removeCachedVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}


	/**
	 * Test AlignVertProps method with different methods
	 */

	public void testAlignVertPropsMergeMethods()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();
		//c.removeAllEdges();

		String testVertex = "v = g.addVertex();" + 
				"v.setProperty(\"name\",\"CVE-1999-0006\");" + 
				"v.setProperty(\"cvssDate\", \"2004-01-01T00:00:00.000-05:00\");" + 
				"v.setProperty(\"references\", \"http://www.securityfocus.com/bid/133\");" +
				"v.setProperty(\"_type\", \"vertex\");" +
				"v.setProperty(\"availabilityImpact\", \"COMPLETE\");" +
				"v.setProperty(\"description\", \"Buffer overflow in POP servers based on BSD/Qualcomm's qpopper allows remote attackers to gain root access using a long PASS command.\");" +
				"v.setProperty(\"source\", \"NVD\");" + 
				"v.setProperty(\"vulnerableSoftware\", \"cpe:/a:qualcomm:qpopper:2.4\");" + 
				"v.setProperty(\"vertexType\", \"vulnerability\");" + 
				"v.setProperty(\"accessComplexity\", \"LOW\");" + 
				"v.setProperty(\"confidentialityImpact\", \"COMPLETE\");" + 
				"v.setProperty(\"cvssScore\", 10);" +
				"v.setProperty(\"accessAuthentication\", \"NONE\");" +
				"v.setProperty(\"modifiedDate\", \"2008-09-09T08:33:31.180-04:00\");" +
				"v.setProperty(\"integrityImpact\", \"COMPLETE\");" +
				"v.setProperty(\"_id\", \"CVE-1999-0006\");" +
				"v.setProperty(\"publishedDate\", \"1998-07-14T00:00:00.000-04:00\");" +
				"v.setProperty(\"accessVector\", \"NETWORK\")";

		c.commit();
		c.execute(testVertex);
		c.commit();

		String id = c.findVertId("CVE-1999-0006");
		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
		a.alignVertProps(id, newProps, mergeMethods);	//id, new properties and how to merge 

		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		mergeMethods.put("testprop", "keepNew");
		testVal = "bbbb";
		newProps.put("testprop", testVal);

		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		c.removeCachedVertices();
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
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		//update a prop (keepNew) (always updates)
		mergeMethods.put("testprop", "keepNew");
		testVal = "bbbb";
		newProps.put("testprop", testVal);

		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		c.removeCachedVertices();
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
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();
		//c.removeAllEdges();

		Map<String, Object> props = new HashMap<String,Object>();
		props.put("NAME", "testvert_align_props");
		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",NAME)", props);
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//update a prop (appendList) (always updates) (list/list case)
		mergeMethods.put("testproparray", "keepNew");
		String[] testArrayVal = {"aaa", "bbb"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		String[] testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		mergeMethods.put("testproparray", "appendList");
		testArrayVal = new String[]{"ccc"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (list/val case)
		mergeMethods.put("testproparray", "keepNew");
		testArrayVal = new String[]{"aaa", "bbb"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		mergeMethods.put("testproparray", "appendList");
		testVal = "ccc";
		newProps.put("testproparray", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (val/list case)
		mergeMethods.put("testproparray", "keepNew");
		testVal = "aaa";
		newProps.put("testproparray", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testproparray");
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		mergeMethods.put("testproparray", "appendList");
		testArrayVal = new String[]{"bbb", "ccc"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb", "ccc"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		//update a prop (appendList) (always updates) (val/val case)
		mergeMethods.put("testproparray", "keepNew");
		testVal = "aaa";
		newProps.put("testproparray", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testproparray");
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		mergeMethods.put("testproparray", "appendList");
		testVal = "bbb";
		newProps.put("testproparray", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testproparray = ((ArrayList<String>)c.getVertByID(id).get("testproparray")).toArray(new String[0]);
		testArrayVal = new String[]{"aaa", "bbb"};
		assertTrue(Arrays.equals(testArrayVal, testproparray));

		c.removeCachedVertices();
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
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		//update a prop (keepUpdates) (update case)
		mergeMethods.put("testprop", "keepUpdates");
		testVal = "bbbb";
		newProps.put("testprop", testVal);
		newProps.put("timestamp", 1001L);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		//update a prop (keepUpdates) (no update case)
		mergeMethods.put("testprop", "keepUpdates");
		testVal = "cccc";
		newProps.put("testprop", testVal);
		newProps.put("timestamp", 999L);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		testVal = "bbbb";
		assertEquals(testVal, testProp);

		c.removeCachedVertices();
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
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
			c = new DBConnection( client );
			a = new Align( c );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeCachedVertices();
		//c.removeAllEdges();

		c.commit();
		c.execute("v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\")");
		c.commit();
		String id = c.findVertId("testvert_align_props");

		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();

		String testVal, testProp;

		//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
		a.alignVertProps(id, newProps, mergeMethods);
		testProp = (String)c.getVertByID(id).get("testprop");
		assertEquals(testVal, testProp);

		//update a prop (keepConfidence) (update case)
		mergeMethods.put("testprop", "keepConfidence");

		//update a prop (keepConfidence) (no update case)
		mergeMethods.put("testprop", "keepConfidence");

		//TODO: this test seems unfinished??

		c.removeCachedVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}

	/**
	 * Testing the keepConfidence option for AlignVertProps
	 */
	/*
	//old method, now uses a config file.  may revisit.
	public void testMergeMethodsFromSchema()
	{
		DBConnection c = null;
		Align a = null;
		try{
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
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
			RexsterClient client = DBConnection.createClient(DBConnection.getTestConfig());
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


