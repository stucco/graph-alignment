package alignment.alignment_v2;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.configuration.BaseConfiguration;
import org.json.*;

import com.tinkerpop.blueprints.Vertex;
import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;

/**
 * Hello world!
 *
 */
public class Align 
{
	
	private RexsterClient client = null;
	private Logger logger = null;
	
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
    	logger = LoggerFactory.getLogger(Align.class);
    	try {
    		List<Map<String,Object>> result;
			logger.info("connecting to DB...");
			client = RexsterClientFactory.open(configOpts);
			
			//configure name index if needed
			List currentIndices = client.execute("g.getIndexedKeys(Vertex.class)");
			logger.info( "found indices: " + currentIndices );
			try{
				if(!currentIndices.contains("name")){ //FIXME must be done earlier?!
					logger.info("name index not found, creating...");
					client.execute("g.makeKey(\"name\").dataType(String.class).indexed(\"standard\",Vertex.class).unique().make();g.commit();g;");
				}
				if(!currentIndices.contains("vertexType")){
					logger.info("vertexType index not found, creating...");
					client.execute("g.makeKey(\"vertexType\").dataType(String.class).indexed(\"standard\",Vertex.class).make();g.commit();g;");
				}
			}catch(Exception e){
				logger.error("could not configure missing indices!", e);
			}
			logger.info(" connection is good!");
		} catch (Exception e) { //open() really just throws Exception?  really?
			this.client = null;
			logger.error("problem creating Rexster connection");
			logger.error("Exception!",e);
		}
    }
    
	@Override
	protected void finalize() throws Throwable {
		client.close();
		client = null;
		super.finalize();
	}
    
	//only needed for tests
	public RexsterClient getClient(){
		return client;
	}
	
    //wrapper to reduce boilerplate
	//TODO wrapper throws away any return value, 
	//  it'd be nice to use this even when we want the query's retval... but then we're back w/ exceptions & don't gain much.
	public boolean execute(String query, Map<String,Object> params){
    	if(this.client == null)
    		return false;
    	try {
    	    //Adding a trailing return 'g' on everything: 
    	    // no execute() args can end up returning null, due to known API bug.
    	    // returning 'g' everywhere is just the simplest workaround for it, since it is always defined.
    		query += ";g";
			client.execute(query, params);
		} catch (RexProException e) {
			logger.error("'execute' method caused a rexpro problem (again)");
			logger.error("Exception!",e);
			return false;
		} catch (IOException e) {
			logger.error("'execute' method caused something new and unexpected to break!");
			logger.error("Exception!",e);
			return false;
		}
    	return true;
    }
    //likewise.
    public boolean execute(String query){
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
    		logger.error("Error parsing GraphSON in load()!");
    		logger.error("The graphson was: " + newGraphSection);
    		logger.error("Exception!",e);
    		return false;
    	}
    	
    	Map<String, Object> param = new HashMap<String, Object>();

    	//for *vertices*, you have a json object that you can load.
    	for(int i=0; i<verts.length; i++){
    		//System.out.println(verts[i]);
    		String vert_name = verts[i].getString("name");
    		boolean new_vert = false;
    		try {
				new_vert = (findVert(vert_name) == null);
			} catch (IOException e) {
				logger.error("Exception!",e);
			} catch (RexProException e) {
				logger.error("Exception!",e);
			}
    		if(new_vert){ //only add new...
    			param.put("VERT_PROPS", verts[i]);
				execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);g.commit()", param);
    		}else{
    			//TODO better to merge instead of ignoring them...
    			logger.warn("Attempted to add a duplicate vertex (within same message) ignoring...");
    		}
    	}
    	//for *edges*, you can't really do that, so find IDs and build a map of needed properties instead.
    	for(int i=0; i<edges.length; i++){
			String outv_id = findVertId(edges[i].getString("_outV"));
			String inv_id = findVertId(edges[i].getString("_inV"));
			if(outv_id == null){
				logger.error("Could not find out_v for edge: " + edges[i]);
				continue;
			}
			if(inv_id == null){
				logger.error("Could not find in_v for edge: " + edges[i]);
				continue;
			}
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
    
    public Map<String, Object> getVertByID(String id){
		try {
			Object query_ret = client.execute("g.v("+id+").map();");
			List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
	    	Map<String, Object> query_ret_map = query_ret_list.get(0);
	    	return query_ret_map;
		} catch (RexProException e) {
			logger.error("Exception!",e);
			return null;
		} catch (IOException e) {
			logger.error("Exception!",e);
			return null;
		} catch (ClassCastException e) {
			logger.error("Exception!",e);
			return null;
		}
    }
    
    public Map<String,Object> findVert(String name) throws IOException, RexProException{
    	if(name == null || name == "")
    		return null;
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("NAME", name);
    	Object query_ret = client.execute("g.V.has(\"name\",NAME).toList();", param);
    	List<Map<String,Object>> query_ret_list = (List<Map<String,Object>>)query_ret;
    	//logger.info("query returned: " + query_ret_list);
    	if(query_ret_list.size() == 0){
    		//logger.info("findVert found 0 matching verts for name:" + name); //this is too noisy, the invoking function can complain if it wants to...
    		return null;
    	}else if(query_ret_list.size() > 1){
    		logger.warn("findVert found more than 1 matching verts for name:" + name);
    		return null;
    	}
    	return query_ret_list.get(0);
    }
    
    public String findVertId(String name){
    	try{
    		return (String)findVert(name).get("_id");
    	}catch(Exception e){
    		logger.warn("Could not find id for name: " + name + ", returning null");
    		return null;
    	}
    }
    
    public void updateVert(String id, Map<String, Object> props){
    	String[] keys = props.keySet().toArray(new String[0]);
    	for(int i=0; i<keys.length; i++){
    		updateVertProperty(id, keys[i], props.get(keys[i]));
    	}
    }
    
    public boolean updateVertProperty(String id, String key, Object val){
    	HashMap<String, Object> param = new HashMap<String, Object>();
    	param.put("ID", id);
    	param.put("KEY", key);
    	param.put("VAL", val);
    	return execute("g.v(ID)[KEY]=VAL;g.commit()", param);
    }
    
    /* unused
    public List findEdge(String name) throws IOException, RexProException{
    	if(name == null || name == "")
    		return null;
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("NAME", name);
    	Object query_ret = client.execute("g.query().has(\"name\",EQUAL,NAME).edges().toList();", param);
    	List query_ret_list = (List)query_ret;
    	logger.info("query returned: " + query_ret_list);
    	return query_ret_list;
    }*/
    
    //mergeMethods are derived from ontology definition
    public void alignVertProps(String vertID, Map<String, Object> newProps, Map<String, String> mergeMethods){
    	Map<String, Object> oldProps = getVertByID(vertID);
    	Iterator<String> k = newProps.keySet().iterator();
		String key;
		while(k.hasNext()){
			key = k.next();
			if(oldProps.containsKey(key)){ //both old & new have this, so check how to merge.
				String mergeMethod = mergeMethods.get(key);
				if(key == "timestamp" || key == "score"){
					//yeah... don't try to merge those here, it breaks things.
					//TODO these will need special handling .... and it will need to be someplace else, after we finish w/ the rest of the vert's props.
				}else if(mergeMethod == null || mergeMethod == "keepNew"){
					oldProps.put(key, newProps.get(key));
				}else if(mergeMethod == "appendList"){ 
					Object oldVal = oldProps.get(key);
					List<Object> oldList;
					if(oldVal instanceof List ){
						oldList = (List<Object>)oldVal;
					}else{
						oldList = new ArrayList<Object>();
						oldList.add(oldVal);
					}
					Object n = newProps.get(key);
					if(n instanceof List){
						oldList.addAll((List<Object>)n);
					}else{
						oldList.add(n);
					}
					oldProps.put(key, oldList);
				}else if(mergeMethod == "keepUpdates"){
					Object oldVal = oldProps.get("timestamp");
					long oldTime = -1;
					if(oldVal instanceof String)
						oldTime = Integer.parseInt((String)oldProps.get("timestamp"));
					else if(oldVal instanceof Long)
						oldTime = (Long)oldVal;
					//TODO else warn?
					long newTime = (Long)newProps.get("timestamp");
					if(newTime >= oldTime){
						oldProps.put(key, newProps.get(key));
					}
				}else if(mergeMethod == "keepConfidence"){
					Object oldVal = oldProps.get("score");
					double oldScore = 0.0;
					if(oldVal instanceof String)
						oldScore = Double.parseDouble((String)oldProps.get("score"));
					else if(oldVal instanceof Double)
						oldScore = (Double)oldVal;
					//TODO else warn?
					double newScore = (Long)newProps.get("score");
					if(newScore >= oldScore){
						oldProps.put(key, newProps.get(key));
					}
				}
			}else{ //else oldProps did not contain this, so just add it.
				oldProps.put(key, newProps.get(key));
			}
		}
		updateVert(vertID, oldProps);
    }
    
    //TODO only needs to be public for testing, will probably make private later.
    //returns a map of prop names to merge methods, for each vert name
    public static Map<String, Map<String, String>> mergeMethodsFromSchema(JSONObject ontology){
		// TODO probably should use an enum type for this.
    	HashMap<String, Map<String, String>> mergeMethods = new HashMap<String, Map<String, String>>();
    	JSONArray verts = ontology.getJSONObject("properties").getJSONObject("vertices").getJSONArray("items");
    	HashMap<String, String> mergeMethodsCurrVert = null;
    	for(int i=0; i<verts.length(); i++){
    		mergeMethodsCurrVert = new HashMap<String, String>();
    		JSONObject currVert = verts.getJSONObject(i);
    		String vertName = currVert.getString("title");
    		JSONObject currProps = currVert.getJSONObject("properties");
    		Iterator<String> k = currProps.keys();
    		while(k.hasNext()){
    			String key = k.next();
    			String method = currProps.getJSONObject(key).optString("merge");
    			if(method == null || method == "")
    				method = "keepNew";
    			mergeMethodsCurrVert.put(key, method);
    		}
    		mergeMethods.put(vertName, mergeMethodsCurrVert);
    	}
    	return mergeMethods;
	}

	public boolean removeAllVertices(){
		return execute("g.V.each{g.removeVertex(it)};g.commit()");
    }
    
    public boolean removeAllEdges(){
		return execute("g.E.each{g.removeVertex(it)};g.commit()");
    }

}
