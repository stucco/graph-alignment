package alignment.alignment_v2;

import java.util.Map;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class ConfigFileLoaderTest 
extends TestCase
{
	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public ConfigFileLoaderTest( String testName )
	{
		super( testName );
	}

	/**
	 * @return the suite of tests being tested
	 */
	public static Test suite()
	{
		return new TestSuite( ConfigFileLoaderTest.class );
	}
	
	

	/**
	 * Tests loading a simple config
	 */
	public void testConfigLoad()
	{
		ConfigFileLoader c = null;
		c = new ConfigFileLoader("../test-classes/alignment.yaml");

		Map<String, Map<String, Object>> property = c.getVertexConfig("user");
		//System.out.println(property);
		//vertexType={comparisonFunction=none, comparisonWeight=0, resolutionFunction=none}, source={comparisonFunction=none, comparisonWeight=0, resolutionFunction=appendList}
		Map<String, Object> vt = property.get("vertexType");
		assertEquals("none", vt.get("comparisonFunction"));
		assertEquals(0, vt.get("comparisonWeight"));
		assertEquals("none", vt.get("resolutionFunction"));
		
		Map<String, Object> src = property.get("source");
		assertEquals("none", src.get("comparisonFunction"));
		assertEquals(0, src.get("comparisonWeight"));
		assertEquals("appendList", src.get("resolutionFunction"));
	}

}


