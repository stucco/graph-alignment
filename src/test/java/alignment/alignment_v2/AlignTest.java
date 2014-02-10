package alignment.alignment_v2;

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
     */
    public void testLoad()
    {
    	Align a = new Align();
    	assertFalse( a.load(null) );
    	assertFalse( a.load("") );
        assertTrue( a.load("a") );
    }
    
    /**
     */
    public void testAlign()
    {
    	Align a = new Align();
    	assertFalse( a.load(null) );
    	assertFalse( a.load("") );
        assertTrue( a.load("a") );
    }
}
