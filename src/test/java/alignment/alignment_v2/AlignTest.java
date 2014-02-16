package alignment.alignment_v2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.tinkerpop.rexster.client.RexProException;

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

    /**
     * Tests loading, querying, and other basic operations for vertices, edges, properties.
     */
    public void testLoad()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
    	a.execute("g.commit();v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_55\");g.commit()");
    	
    	String test_graphson_verts = " {\"vertices\":[" +
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
			      "},{"+
			      "\"_id\":\"CVE-1999-nnnn\"," +
			      "\"_type\":\"vertex\","+
			      "\"source\":\"CVE\","+
			      "\"description\":\"test description asdf.\","+
			      "\"references\":["+
			        "\"http://www.google.com\"],"+
			      "\"status\":\"Entry\","+
			      "\"score\":1.0"+
			      "}"+
			      "],"+
			      "\"edges\":["+
			      "{"+ 
			      "\"_id\":\"asdf\"," +
			      "\"_inV\":\"CVE-1999-0002\"," +
			      "\"_outV\":\"CVE-1999-nnnn\"," +
			      "\"_label\":\"some_label_asdf\","+
			      "\"some_property\":\"some_value\""+
			      "}"+
			      "]}";
    	a.load(test_graphson_verts);
    	
		try {
			Object query_ret;
			//find this node, check some properties.
			String id = a.findVertId("CVE-1999-0002");
			query_ret = a.getClient().execute("g.v("+id+").map();");
			List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
			Map<String, Object> query_ret_map = query_ret_list.get(0);
			assertEquals("Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.", query_ret_map.get("description"));
			String[] expectedRefs = {"CERT:CA-98.12.mountd","http://www.ciac.org/ciac/bulletins/j-006.shtml","http://www.securityfocus.com/bid/121","XF:linux-mountd-bo"};
			String[] actualRefs = ((ArrayList<String>)query_ret_map.get("references")).toArray(new String[0]);
			assertTrue(Arrays.equals(expectedRefs, actualRefs));
			//find the other node, check its properties.
			String id2 = a.findVertId("CVE-1999-nnnn");
			query_ret = a.getClient().execute("g.v("+id2+").map();");
			query_ret_list = (List<Map<String, Object>>)query_ret;
			query_ret_map = query_ret_list.get(0);
			assertEquals("test description asdf.", query_ret_map.get("description"));
			expectedRefs = new String[]{"http://www.google.com"};
			actualRefs = ((ArrayList<String>)query_ret_map.get("references")).toArray(new String[0]);
			assertTrue(Arrays.equals(expectedRefs, actualRefs));
			//and now test the edge between them
			query_ret = a.getClient().execute("g.v("+id2+").outE().inV();");
			query_ret_list = (List<Map<String, Object>>)query_ret;
			query_ret_map = query_ret_list.get(0);
			assertEquals(id, query_ret_map.get("_id"));
		} catch (RexProException e) {
			fail("RexProException");
			e.printStackTrace();
		} catch (IOException e) {
			fail("IOException");
			e.printStackTrace();
		}
    	
    	//System.out.println("CVE-1999-0002 has id of " + id);

    }
    
    /**
     * Tests updating vertex properties
     */
    public void testUpdate()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
		try {
			a.execute("g.commit();v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_55\");g.commit()");
	    	
			Object query_ret;
			String id = a.findVertId("testvert_55");
			query_ret = a.getClient().execute("g.v("+id+").map();");
			List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
			Map<String, Object> query_ret_map = query_ret_list.get(0);
			assertEquals( "55", query_ret_map.get("z").toString());
			
			Map<String, Object> newProps = new HashMap<String, Object>();
			newProps.put("y", "33");
			newProps.put("z", "44");
			a.updateVert(id, newProps);
			
			query_ret = a.getClient().execute("g.v("+id+").map();");
			query_ret_list = (List<Map<String, Object>>)query_ret;
			query_ret_map = query_ret_list.get(0);
			assertEquals("33", query_ret_map.get("y").toString());
			assertEquals("44", query_ret_map.get("z").toString());
			
		} catch (RexProException e) {
			fail("RexProException");
			e.printStackTrace();
		} catch (IOException e) {
			fail("IOException");
			e.printStackTrace();
		}
    	
    }
    
    /**
     * Testing the keepNew option for AlignVertProps
     */
    public void testAlignVertPropsKeepNew()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
		a.execute("g.commit();v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_align_props\");g.commit()");
		String id = a.findVertId("testvert_align_props");
		
		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();
		
		String testVal, testProp;
		
    	//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	assertEquals(testVal, testProp);
    	
    	//update a prop (keepNew) (always updates)
    	mergeMethods.put("testprop", "keepNew");
		testVal = "bbbb";
		newProps.put("testprop", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	assertEquals(testVal, testProp);
    	
    }
    
    /**
     * Testing the appendList option for AlignVertProps
     */
    public void testAlignVertPropsAppendList()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
		a.execute("g.commit();v = g.addVertex();v.setProperty(\"z\",55);v.setProperty(\"name\",\"testvert_align_props\");g.commit()");
		String id = a.findVertId("testvert_align_props");
		
		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();
		
		String testVal, testProp;
    	
    	//update a prop (appendList) (always updates) (list/list case)
    	mergeMethods.put("testproparray", "keepNew");
    	String[] testArrayVal = {"aaa", "bbb"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
    	a.alignVertProps(id, newProps, mergeMethods);
    	String[] testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	mergeMethods.put("testproparray", "appendList");
    	testArrayVal = new String[]{"ccc"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
    	a.alignVertProps(id, newProps, mergeMethods);
    	testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	testArrayVal = new String[]{"aaa", "bbb", "ccc"};
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	//update a prop (appendList) (always updates) (list/val case)
    	mergeMethods.put("testproparray", "keepNew");
    	testArrayVal = new String[]{"aaa", "bbb"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
    	a.alignVertProps(id, newProps, mergeMethods);
    	testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	mergeMethods.put("testproparray", "appendList");
    	testVal = "ccc";
		newProps.put("testproparray", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	testArrayVal = new String[]{"aaa", "bbb", "ccc"};
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	//update a prop (appendList) (always updates) (val/list case)
    	mergeMethods.put("testproparray", "keepNew");
    	testVal = "aaa";
		newProps.put("testproparray", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testproparray");
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	mergeMethods.put("testproparray", "appendList");
    	testArrayVal = new String[]{"bbb", "ccc"};
		newProps.put("testproparray", Arrays.asList(testArrayVal));
    	a.alignVertProps(id, newProps, mergeMethods);
    	testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	testArrayVal = new String[]{"aaa", "bbb", "ccc"};
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	//update a prop (appendList) (always updates) (val/val case)
    	mergeMethods.put("testproparray", "keepNew");
    	testVal = "aaa";
		newProps.put("testproparray", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testproparray");
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    	mergeMethods.put("testproparray", "appendList");
    	testVal = "bbb";
		newProps.put("testproparray", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testproparray = ((ArrayList<String>)a.getVertByID(id).get("testproparray")).toArray(new String[0]);
    	testArrayVal = new String[]{"aaa", "bbb"};
    	assertTrue(Arrays.equals(testArrayVal, testproparray));
    	
    }
    
    /**
     * Testing the keepUpdates option for AlignVertProps
     */
    public void testAlignVertPropsKeepUpdates()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
		a.execute("g.commit();v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\");g.commit()");
		String id = a.findVertId("testvert_align_props");
		
		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();
		
		String testVal, testProp;
		
    	//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	assertEquals(testVal, testProp);
    	
    	//update a prop (keepUpdates) (update case)
    	mergeMethods.put("testprop", "keepUpdates");
    	testVal = "bbbb";
		newProps.put("testprop", testVal);
		newProps.put("timestamp", 1001L);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	assertEquals(testVal, testProp);
    	
    	//update a prop (keepUpdates) (no update case)
    	mergeMethods.put("testprop", "keepUpdates");
    	testVal = "cccc";
		newProps.put("testprop", testVal);
		newProps.put("timestamp", 999L);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	testVal = "bbbb";
    	assertEquals(testVal, testProp);
    }
    
    /**
     * Testing the keepConfidence option for AlignVertProps
     */
    public void testAlignVertPropsKeepConfidence()
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
		a.execute("g.commit();v = g.addVertex();v.setProperty(\"timestamp\",1000L);v.setProperty(\"name\",\"testvert_align_props\");g.commit()");
		String id = a.findVertId("testvert_align_props");
		
		Map<String, String> mergeMethods = new HashMap<String,String>();
		Map<String, Object> newProps = new HashMap<String,Object>();
		
		String testVal, testProp;
		
    	//add a new prop
		testVal = "aaaa";
		newProps.put("testprop", testVal);
    	a.alignVertProps(id, newProps, mergeMethods);
    	testProp = (String)a.getVertByID(id).get("testprop");
    	assertEquals(testVal, testProp);
    	
    	//update a prop (keepConfidence) (update case)
    	mergeMethods.put("testprop", "keepConfidence");
    	
    	//update a prop (keepConfidence) (no update case)
    	mergeMethods.put("testprop", "keepConfidence");
    	
    }
}
