package alignment.alignment_v2;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.BaseConfiguration;
import org.json.*;

import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.msg.RexProMessage;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;

/**
 * Hello world!
 *
 */
public class Align 
{
	
	private RexsterClient client = null;
	
	//TODO: these timeouts seem to do nothing.  If the server is down, it seems to wait (& apparently retry) forever.
	// should probably submit a bug report for this.
    private static final BaseConfiguration configOpts = new BaseConfiguration() {{
        addProperty(RexsterClientTokens.CONFIG_HOSTNAME, "localhost");
        addProperty(RexsterClientTokens.CONFIG_PORT, 8184);
        addProperty(RexsterClientTokens.CONFIG_TIMEOUT_CONNECTION_MS, 8000);
        addProperty(RexsterClientTokens.CONFIG_TIMEOUT_WRITE_MS, 4000);
        addProperty(RexsterClientTokens.CONFIG_TIMEOUT_READ_MS, 16000);
        addProperty(RexsterClientTokens.CONFIG_MAX_ASYNC_WRITE_QUEUE_BYTES, 512000);
        addProperty(RexsterClientTokens.CONFIG_MESSAGE_RETRY_COUNT, 4);
        addProperty(RexsterClientTokens.CONFIG_MESSAGE_RETRY_WAIT_MS, 50);
        addProperty(RexsterClientTokens.CONFIG_LANGUAGE, "groovy");
        addProperty(RexsterClientTokens.CONFIG_GRAPH_OBJECT_NAME, "g");
        addProperty(RexsterClientTokens.CONFIG_GRAPH_NAME, "graph"); //not rename-able?  Seems like a Titan thing?
        addProperty(RexsterClientTokens.CONFIG_TRANSACTION, true);
        addProperty(RexsterClientTokens.CONFIG_SERIALIZER, MsgPackSerializer.SERIALIZER_ID);
    }};
    
    public Align(){
    	try {
    		List<Map<String,Object>> result;
			System.out.print("connecting to DB...");
			client = RexsterClientFactory.open(configOpts);
			
			//call execute() with some stuff we don't care about, 
			//  to make sure that the connection is actually good.
			//  (open() method doesn't actually do anything other than make the client object)
			result = client.execute("g.V('name','some node with a long name that should not exist')");
			//System.out.println("got result: " + result.toString()); //don't really care...
			System.out.println(" connection is good!");
			
		} catch (Exception e) { //open() really just throws Exception?  really?
			this.client = null;
			System.err.println("problem testing Rexster connection");
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
	@Override
	protected void finalize() throws Throwable {
		client.close();
		client = null;
		super.finalize();
	}
    
    //wrapper to reduce boilerplate
	//TODO wrapper throws away any return value, 
	//  it'd be nice to use this even when we want the query's retval... but then we're back w/ exceptions & don't gain much.
    private boolean execute(String query, Map<String,Object> params){
    	if(this.client == null)
    		return false;
    	try {
			client.execute(query, params);
		} catch (RexProException e) {
			System.err.println("'execute' method caused a rexpro problem (again)");
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			System.err.println("'execute' method caused something new and unexpected to break!");
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
    	return true;
    }
    //likewise.
    private boolean execute(String query){
    	return execute(query,null);
    }
	
    public boolean load(String newGraphSection){
    	//do all the json obj parsing up front, in case you need to panic & leave early.
    	if(newGraphSection == null || newGraphSection == "")
    		return false;
    	int vertCount = 0;
    	JSONObject[] verts = new JSONObject[0];
    	int edgeCount = 0;
    	JSONObject[] edges = new JSONObject[0];
    	try{
	    	JSONObject graphson = new JSONObject(newGraphSection);
	    	//make array of verts...
	    	JSONArray json_verts = (JSONArray) graphson.opt("vertices");
	    	if(json_verts != null){
	    		vertCount = json_verts.length();
	    		verts = new JSONObject[vertCount];
	    		for(int i=0; i<vertCount; i++) 
	    			verts[i] = (JSONObject)json_verts.get(i);
	    	}
	    	//...and likewise for edges
	    	JSONArray json_edges = (JSONArray) graphson.opt("edges");
	    	if(json_edges != null){
	    		edgeCount = json_edges.length();
	    		edges = new JSONObject[edgeCount];
	    		for(int i=0; i<edgeCount; i++) 
	    			edges[i] = (JSONObject)json_edges.get(i);
	    	}
    	}catch(Exception e){
    		//TODO fail with less panic?
    		System.err.println("Error parsing GraphSON in load()!");
    		e.printStackTrace();
    		return false;
    	}
    	
    	Map<String, Object> param = new HashMap<String, Object>();

    	//lolnope, no way to pass a graphson string to this, only a string of a path to a graphson file.  I thought that sounded too easy...
		//execute("g.commit();g.loadGraphSON(PARAM_GRAPHSON);g.commit();g", param);
		
		//this looks like it should work from the documentation?  but doesn't?
		//execute("g.commit();g.addVertex(null, VERT_PROPS);g.commit();g", param);
		
    	for(int i=0; i<verts.length; i++){
			param.put("VERT_PROPS", verts[i]);
			//oh wow.  another magic undocumented convenience method that does the obvious thing in a non-obvious way.
			execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);g.commit();g", param);
    	}
    	for(int i=0; i<edges.length; i++){
			param.put("EDGE_PROPS", edges[i]);
			//execute("v = GraphSONUtility.edgeFromJson(EDGE_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);g.commit();g", param);
			//TODO I doubt the above will work as-is, probably need more handling to get references to in/out verts.
    	}
    	
    	return true;//TODO what if some execute()s pass and some fail?
    }
    
    //TODO: stub.
    public boolean find(String newGraphSection){
    	if(newGraphSection == null || newGraphSection == "")
    		return false;
    	return true;
    }
    
    public boolean align(String newGraphSection){
    	if(this.client == null)
    		return false;
    	if(newGraphSection == null || newGraphSection == "")
    		return false;
    	return true;
    }
    
    public boolean removeAllVertices(){
		return execute("g.V.each{g.removeVertex(it)};g.commit();g");
    }
    
    //Note the commit() and trailing return 'g' - these are not well documented anywhere I've seen, but they are required just about everywhere! 
    public boolean removeAllEdges(){
		return execute("g.E.each{g.removeVertex(it)};g.commit();g");
    }
    
    //will remove this later
    public static void main( String[] args )
    {
    	Align a = new Align();
    	a.removeAllVertices();
    	a.removeAllEdges();
    	
    	a.execute("g.commit();g.addVertex().setProperty(\"z\",55);g.commit();g");
    	
    	String test_graphson = " {\"vertices\":[" +
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
			      "}]}";
    	a.load(test_graphson);
    	
        System.out.println( "Done!" );
    }

}
