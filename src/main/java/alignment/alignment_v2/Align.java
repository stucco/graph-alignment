package alignment.alignment_v2;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
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
    	    //Adding a trailing return 'g' on everything: 
    	    // no execute() args can end up returning null, due to known API bug.
    	    // returning 'g' everywhere is just the simplest workaround for it, since it is always defined.
    		query += ";g";
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
    	int vertCount = 0;
    	JSONObject[] verts = new JSONObject[0];
    	int edgeCount = 0;
    	JSONObject[] edges = new JSONObject[0];
    	try{
	    	JSONObject graphson = new JSONObject(newGraphSection);
	    	//make array of verts...
	    	JSONArray json_verts = graphson.optJSONArray("vertices");
	    	if(json_verts != null){
	    		vertCount = json_verts.length();
	    		verts = new JSONObject[vertCount];
	    		for(int i=0; i<vertCount; i++){
	    			verts[i] = (JSONObject)json_verts.get(i);
	    			verts[i].put("name", verts[i].get("_id"));
	    		}
	    	}
	    	//...and likewise for edges
	    	JSONArray json_edges = graphson.optJSONArray("edges");
	    	if(json_edges != null){
	    		edgeCount = json_edges.length();
	    		edges = new JSONObject[edgeCount];
	    		for(int i=0; i<edgeCount; i++) 
	    			edges[i] = (JSONObject)json_edges.get(i);
	    	}
    	}catch(Exception e){ 
    		//we want *any* graphson problems to end up here
    		//being noisy when these fail is probably ok, we shouldn't really ever fail here except when testing, etc.
    		//TODO but really all of these errors should go to our slf4j stuff instead... 
    		System.err.println("Error parsing GraphSON in load()!");
    		System.err.println("The graphson was: " + newGraphSection);
    		e.printStackTrace();
    		return false;
    	}
    	
    	Map<String, Object> param = new HashMap<String, Object>();

    	//for *vertices*, you have a json object that you can load.
    	for(int i=0; i<verts.length; i++){
			param.put("VERT_PROPS", verts[i]);
			execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);g.commit()", param);
    	}
    	//for *edges*, you can't really do that, so find IDs and build a map of needed properties instead.
    	for(int i=0; i<edges.length; i++){
			String outv_id = findVertId(edges[i].getString("_outV"));
			String inv_id = findVertId(edges[i].getString("_inV"));
			String label = edges[i].optString("_label");
			param.put("OUTV", outv_id);
			param.put("INV", inv_id);
			param.put("LABEL", label);
			//build your param map obj
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("name", edges[i].get("_id"));
			edges[i].remove("_inv");
			edges[i].remove("_outv");
			edges[i].remove("_id");
			Iterator<String> k = edges[i].keys();
			String key;
			while(k.hasNext()){
				key = k.next();
				props.put(key, edges[i].get(key));
			}
			param.put("EDGE_PROPS", props);
			//and now finally add edge to graph
			execute("outv = g.v(OUTV); inv = g.v(INV);g.addEdge(outv,inv,LABEL,EDGE_PROPS);g.commit()", param);
    	}
    	return true;//TODO what if some execute()s pass and some fail?
    }
    
    public List findVert(String name) throws IOException, RexProException{
    	if(name == null || name == "")
    		return null;
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("NAME", name);
    	Object query_ret = client.execute("g.query().has(\"name\",NAME).vertices().toList();", param);
    	List query_ret_list = (List)query_ret;
    	System.out.println("query returned: " + query_ret_list);
    	return query_ret_list;
    }
    
    public String findVertId(String name){
    	try{
    		Map query_ret = (Map)(findVert(name).get(0));
    		return (String)query_ret.get("_id");
    	}catch(Exception e){
    		System.err.println("Warn: could not find id for name: " + name + ", returning null");
    		return null;
    	}
    }
    
    /* unused
    public List findEdge(String name) throws IOException, RexProException{
    	if(name == null || name == "")
    		return null;
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("NAME", name);
    	Object query_ret = client.execute("g.query().has(\"name\",NAME).edges().toList();", param);
    	List query_ret_list = (List)query_ret;
    	System.out.println("query returned: " + query_ret_list);
    	return query_ret_list;
    }*/
    
    public boolean align(String newGraphSection){
    	if(this.client == null)
    		return false;
    	if(newGraphSection == null || newGraphSection == "")
    		return false;
    	return true;
    }
    
    public boolean removeAllVertices(){
		return execute("g.V.each{g.removeVertex(it)};g.commit()");
    }
    
    public boolean removeAllEdges(){
		return execute("g.E.each{g.removeVertex(it)};g.commit()");
    }
    
    //will remove this later
    public static void main( String[] args ) throws IOException, RexProException
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
    	
    	String id = a.findVertId("CVE-1999-0002");
    	System.out.println("CVE-1999-0002 has id of " + id);
    	
        System.out.println( "Done!" );
    }

}
