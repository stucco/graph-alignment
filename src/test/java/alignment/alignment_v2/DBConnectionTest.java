package alignment.alignment_v2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;

import com.tinkerpop.rexster.client.RexProException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class DBConnectionTest 
extends TestCase
{
	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public DBConnectionTest( String testName )
	{
		super( testName );
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite()
	{
		return new TestSuite( DBConnectionTest.class );
	}



	/**
	 * Tests loading, querying, and other basic operations for vertices, edges, properties.
	 */
	public void testLoad()
	{
		DBConnection c = null;
		try{
			c = new DBConnection( DBConnection.getTestClient() );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		String vert1 = "{" +
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
				"}";
		String vert2 = "{"+
				"\"_id\":\"CVE-1999-nnnn\"," +
				"\"_type\":\"vertex\","+
				"\"source\":\"CVE\","+
				"\"description\":\"test description asdf.\","+
				"\"references\":["+
				"\"http://www.google.com\"],"+
				"\"status\":\"Entry\","+
				"\"score\":1.0"+
				"}";
		String edge = "{"+ 
				"\"_id\":\"asdf\"," +
				"\"_inV\":\"CVE-1999-0002\"," +
				"\"_outV\":\"CVE-1999-nnnn\"," +
				"\"_label\":\"some_label_asdf\","+
				"\"some_property\":\"some_value\""+
				"}";
		c.addVertexFromJSON(new JSONObject(vert1));
		c.addVertexFromJSON(new JSONObject(vert2));
		c.commit();
		c.addEdgeFromJSON(new JSONObject(edge));
		c.commit();

		try {
			//find this node, check some properties.
			String id = c.findVertId("CVE-1999-0002");
			Map<String, Object> query_ret_map = c.getVertByID(id);
			String[] expectedRefs = {"CERT:CA-98.12.mountd","http://www.ciac.org/ciac/bulletins/j-006.shtml","http://www.securityfocus.com/bid/121","XF:linux-mountd-bo"};
			String[] actualRefs = ((ArrayList<String>)query_ret_map.get("references")).toArray(new String[0]);
			assertTrue(Arrays.equals(expectedRefs, actualRefs));

			//find the other node, check its properties.
			String id2 = c.findVertId("CVE-1999-nnnn");
			query_ret_map = c.getVertByID(id2);
			assertEquals("test description asdf.", query_ret_map.get("description"));
			expectedRefs = new String[]{"http://www.google.com"};
			actualRefs = ((ArrayList<String>)query_ret_map.get("references")).toArray(new String[0]);
			assertTrue(Arrays.equals(expectedRefs, actualRefs));

			//and now test the edge between them
			Object query_ret;
			query_ret = c.getClient().execute("g.v("+id2+").outE().inV();");
			//System.out.println("query ret is: " + query_ret);
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


	/**
	 * Tests updating vertex properties
	 */

	public void testUpdate()
	{
		DBConnection c = null;
		try{
			c = new DBConnection( DBConnection.getTestClient() );
		}catch(Exception e){
			e.printStackTrace(); //TODO
		} //the possible NPE below is fine, don't care if test errors.

		c.removeAllVertices();
		//c.removeAllEdges();

		c.execute("g.commit();v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_55\");g.commit()");

		String id = c.findVertId("testvert_55");
		Map<String, Object> query_ret_map = c.getVertByID(id);
		assertEquals( "55", query_ret_map.get("z").toString());

		Map<String, Object> newProps = new HashMap<String, Object>();
		newProps.put("y", "33");
		newProps.put("z", "44");
		c.updateVert(id, newProps);

		query_ret_map = c.getVertByID(id);
		assertEquals("33", query_ret_map.get("y").toString());
		assertEquals("44", query_ret_map.get("z").toString());

		c.removeAllVertices();
		//DBConnection.closeClient(this.client); //can close now, instead of waiting for finalize() to do it
	}


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
			c = new DBConnection( DBConnection.getTestClient() );
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
			String id = a.findVertId("CVE-2006-3459");
			Map<String, Object> query_ret_map = a.getVertByID(id);
			assertEquals("Metasploit", query_ret_map.get("source"));
			assertEquals("vulnerability", query_ret_map.get("vertexType"));

			//find this other node, check its properties.
			String id2 = a.findVertId("exploit/apple_ios/email/mobilemail_libtiff");
			query_ret_map = a.getVertByID(id2);
			assertEquals("Metasploit", query_ret_map.get("source"));
			assertEquals("malware", query_ret_map.get("vertexType"));
			assertEquals("exploit", query_ret_map.get("malwareType"));
			assertEquals("2006-08-01 00:00:00", query_ret_map.get("discoveryDate"));
			assertEquals("Apple iOS MobileMail LibTIFF Buffer Overflow", query_ret_map.get("shortDescription"));
			assertEquals("This module exploits a buffer overflow in the version of libtiff shipped with firmware versions 1.00, 1.01, 1.02, and 1.1.1 of the Apple iPhone. iPhones which have not had the BSD tools installed will need to use a special payload.", query_ret_map.get("fullDescription"));

			//and now test the edge between them
			Object query_ret;
			query_ret = this.client.execute("g.v("+id2+").outE().inV();");
			List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
			query_ret_map = query_ret_list.get(0);
			assertEquals(id, query_ret_map.get("_id"));

			a.removeAllVertices();
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


