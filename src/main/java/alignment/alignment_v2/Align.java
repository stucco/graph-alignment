package alignment.alignment_v2;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.io.FileUtils;
import org.apache.commons.configuration.AbstractConfiguration;
import org.apache.commons.configuration.BaseConfiguration;
import org.apache.tools.ant.types.Path;
import org.json.*;

import com.tinkerpop.blueprints.Vertex;
import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;

import org.yaml.snakeyaml.Yaml;

import alignmentStudy.*;
/**
 * Connects to Graph DB, aligns and adds new incoming graph data, provides some misc. utility functions.
 *
 */
public class Align 
{										
	
	private RexsterClient client = null;
	private Logger logger = null;
	private Map<String, String> vertIDCache = null;
	private ConfigFileLoader config = null;
	
	//TODO: these timeouts seem to do nothing.  If the server is down, it seems to wait (& apparently retry) forever.
	// should probably submit a bug report for this.
    private static final BaseConfiguration configOpts = new BaseConfiguration() {{
        addProperty(RexsterClientTokens.CONFIG_HOSTNAME, "localhost");
        addProperty(RexsterClientTokens.CONFIG_PORT, 8184);
        addProperty(RexsterClientTokens.CONFIG_TIMEOUT_CONNECTION_MS, 18000);
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
    
    public Align() {
    	
    	//loading configuration file into HashMap

    	logger = LoggerFactory.getLogger(Align.class);
    	vertIDCache = new HashMap<String, String>(10000);
    	config = new ConfigFileLoader();
    	
    	try {
    		List<Map<String,Object>> result;
			logger.info("connecting to DB...");
			client = RexsterClientFactory.open(configOpts);		//created at the beginning of the file
	//		System.out.println("client" + client);
			//configure vert indices needed
			//List currentIndices = client.execute("g.getManagementSystem().getGraphIndexes(Vertex.class)");
			List currentIndices = client.execute("g.getIndexedKeys(Vertex.class)");
		
			logger.info( "found vertex indices: " + currentIndices );
			try{
		//		System.out.println("currentIndices = " + currentIndices +  " " + "name");
				if(!currentIndices.contains("name")){
					logger.info("name index not found, creating...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "name = mgmt.makePropertyKey(\"name\").dataType(String.class).make();"
							+ "mgmt.buildIndex(\"byName\",Vertex.class).addKey(name).unique().buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}
				if(!currentIndices.contains("vertexType")){
					logger.info("vertexType index not found, creating...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "vertexType = mgmt.makePropertyKey(\"vertexType\").dataType(String.class).make();"
							+ "mgmt.buildIndex(\"byVertexType\",Vertex.class).addKey(vertexType).buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}
				if(!currentIndices.contains("name") || !currentIndices.contains("vertexType")){
					logger.info("name or vertexType index not found, creating combined index...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "name = mgmt.getPropertyKey(\"name\");"
							+ "vertexType = mgmt.getPropertyKey(\"vertexType\");"
							+ "mgmt.buildIndex(\"byNameAndVertexType\",Vertex.class).addKey(name).addKey(vertexType).unique().buildCompositeIndex();"
							+ "mgmt.commit();g;"); //TODO: not convinced that this (new) index really works, need to test further.  but it's currently unused, so leaving as-is for now.
				}
			}catch(Exception e){
				logger.error("could not configure missing vertex indices!", e);
			}
			/*
			currentIndices = client.execute("g.getIndexedKeys(Edge.class)");
			logger.info( "found edge indices: " + currentIndices );
			try{
				if(!currentIndices.contains("name")){
					logger.info("name index not found, creating...");
					client.execute("g.makeKey(\"edgeName\").dataType(String.class).indexed(\"standard\",Edge.class).unique().make();g.commit();g;");
				}
			}catch(Exception e){
				logger.error("could not configure missing indices!", e);
			}
			*/
			logger.info(" connection is good!");
		} catch (Exception e) { //open() really just throws Exception?  really?
			this.client = null;
			logger.error("problem creating Rexster connection");
			logger.error("Exception!",e);
		}
    }
    
	@Override
	protected void finalize() throws Throwable {
		closeClient();
		super.finalize();
	}
    
	//only needed for tests
	public RexsterClient getClient(){
		return client;
	}
	
	//only public for tests
	public void closeClient(){
		if(client != null){
			try {
				client.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			client = null;
		}
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
			logger.error("this query was: " + query + " params were: " + params);
			logger.error("Exception!",e);
			return false;
		} catch (IOException e) {
			logger.error("'execute' method caused something new and unexpected to break!");
			logger.error("this query was: " + query + " params were: " + params);
			logger.error("Exception!",e);
			return false;
		}
    	return true;
    }
    //likewise.
    public boolean execute(String query){
    	return execute(query,null);
    }
	
 //   public void printGraph()	{
 //   	int i = 1;
 //   	for (String key : vertIDCache.keySet())	{
  //  		System.out.println(i + " key = " + key + "; value = " + vertIDCache.get(key));
  //  		i++;
  //  	}
 //   }
    
    
    public boolean load(String newGraphSection){
    	
    	//do all the json obj parsing up front, in case you need to panic & leave early.
    	int vertCount = 0;
    	JSONObject[] verts = new JSONObject[0];
    	int edgeCount = 0;
    	JSONObject[] edges = new JSONObject[0];
    	try{
	    	JSONObject graphson = new JSONObject(newGraphSection);
	    	JSONArray json_verts = graphson.optJSONArray("vertices");
	    	
	    	if(json_verts != null){			//if there are vertices
	    		vertCount = json_verts.length(); //count how many of them
	    		verts = new JSONObject[vertCount];	//create an array of JSONObjects[how many vertexes]
	    		for(int i=0; i<vertCount; i++){		//in every vertex 
	    			verts[i] = (JSONObject)json_verts.get(i);	//place vertex json object
	    	//		System.out.println("vertex id = " + verts[i].get("_id"));
	    			verts[i].put("name", verts[i].get("_id"));	//add "name" field equals its ID
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
			new_vert = (findVertId(vert_name) == null);
    		if(new_vert){ //only add new...
    			param.put("VERT_PROPS", verts[i]);
			execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null)", param);
		}else{
    			//TODO need to call alignVertProps() for this case, which means we need to make a mergeMethods obj
    			logger.debug("Attempted to add vertex with duplicate name.  ignoring ...");
    		}
    		if(i%150 == 0){
    			execute("g.commit()");//only commit periodically, so that operations can be combined by Titan.
    		}
    	}
    	execute("g.commit()"); //make sure all verts are committed before proceeding.
    	
    	param = new HashMap<String, Object>();
    	//for *edges*, you can't really do that, so find IDs and build a map of needed properties instead.
    	for(int i=0; i<edges.length; i++){
			String outv_id = findVertId(edges[i].getString("_outV"));
			String inv_id = findVertId(edges[i].getString("_inV"));
			String edgeName = edges[i].getString("_id");
			System.out.println("ID = " + edgeName);
			//String edgeID = findEdgeId(edgeName);
			if(outv_id == null){
				logger.error("Could not find out_v for edge: " + edges[i]);
				continue;
			}
			if(inv_id == null){
				logger.error("Could not find in_v for edge: " + edges[i]);
				continue;
			}
			String label = edges[i].optString("_label");
			if(edgeExists(inv_id, outv_id, label)){
				//TODO need to merge edge props for this case, like verts above...
				logger.debug("Attempted to add edge with duplicate name.  ignoring ...");
				continue;
			}
			param.put("ID_OUT", Integer.parseInt(outv_id));
			param.put("ID_IN", Integer.parseInt(inv_id));
			param.put("LABEL", label);
			//build your param map obj
			Map<String, Object> props = new HashMap<String, Object>();
			props.put("edgeName", edgeName);
			edges[i].remove("_inv");
			edges[i].remove("_outv");
			edges[i].remove("_id");
			Iterator<String> k = edges[i].keys();
			String key;
			while(k.hasNext()){
				key = k.next();
				props.put(key, edges[i].get(key));
			//	System.out.println(key);
			}
			param.put("EDGE_PROPS", props);
			//and now finally add edge to graph
			execute("g.addEdge(g.v(ID_OUT),g.v(ID_IN),LABEL,EDGE_PROPS)", param);
    		if(i%150 == 0){
    			execute("g.commit()");//only commit periodically, so that operations can be combined by Titan.
    		}
    	}
    	execute("g.commit()"); //make sure all edges are committed also.
    	
	System.out.println("size of cacheIDCache = " + vertIDCache.size());

    	return true;//TODO what if some execute()s pass and some fail?
    }

	public Map<String, Object> getVertByID(String id){
		try {
			Map<String, Object> param = new HashMap<String, Object>();
	    	param.put("ID", Integer.parseInt(id));
			Object query_ret = client.execute("g.v(ID).map();", param);
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
    	Object query_ret = client.execute("g.query().has(\"name\",NAME).vertices().toList();", param);
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
    
    /*
    public Map<String,Object> findEdge(String edgeName) throws IOException, RexProException{
    	if(edgeName == null || edgeName == "")
    		return null;
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("NAME", edgeName);
    	Object query_ret = client.execute("g.query().has(\"name\",NAME).edges().toList();", param);
    	List<Map<String,Object>> query_ret_list = (List<Map<String,Object>>)query_ret;
    	//logger.info("query returned: " + query_ret_list);
    	if(query_ret_list.size() == 0){
    		//logger.info("findEdge found 0 matching edges for name:" + name); //this is too noisy, the invoking function can complain if it wants to...
    		return null;
    	}else if(query_ret_list.size() > 1){
    		logger.warn("findEdge found more than 1 matching edges for name:" + edgeName);
    		return null;
    	}
    	return query_ret_list.get(0);
    }
    */

    //function is searching vertIDCache first, if id is not in there, then it is calling the findVert funciton
    public String findVertId(String name){
    	String id = vertIDCache.get(name);
    	
  //  	for (String key: vertIDCache.keySet()){
  //  		System.out.println("key = " + key + " value = " + vertIDCache.get(key));
  //  	}
    	
    	if(id != null){
    		return id;
    	}else{
	    	try{
	    		Map<String, Object> vert = findVert(name);
	    		if(vert == null) 
	    			id = null;
	    		else 
	    			id = (String)vert.get("_id");
	    		if(id != null){
	    			//TODO cache eviction, and/or limit caching by vert type.  But until vertex count gets higher, it won't matter much.
	    			vertIDCache.put(name, id);
	    		}
	    		return id;
	    	}catch(RexProException e){
	    		logger.warn("RexProException in findVertID (with name: " + name + " )", e);
	    		return null;
	    	}catch(NullPointerException e){
	    		logger.error("NullPointerException in findVertID (with name: " + name + " )", e);
	    		return null;
	    	}catch(IOException e){
	    		logger.error("IOException in findVertID (with name: " + name + " )", e);
	    		return null;
	    	}
    	}
    }
    
    /*
    public String findEdgeId(String edgeName){
    	String id = null;
    	try{
    		Map<String, Object> edge = findEdge(edgeName);
    		if(edge == null) 
    			id = null;
    		else 
    			id = (String)edge.get("_id");
    		return id;
    	}catch(RexProException e){
    		logger.warn("RexProException in findEdgeId (with name: " + edgeName + " )", e);
    		return null;
    	}catch(NullPointerException e){
    		logger.error("NullPointerException in findEdgeId (with name: " + edgeName + " )", e);
    		return null;
    	}catch(IOException e){
    		logger.error("IOException in findEdgeId (with name: " + edgeName + " )", e);
    		return null;
    	}
    }
    */
    
    private boolean edgeExists(String inv_id, String outv_id, String label) {
    	if(inv_id == null || inv_id == "" || outv_id == null || outv_id == "" || label == null || label == "")
    		return false;
  
    	Map<String, Object> param = new HashMap<String, Object>();
    	param.put("ID_IN", Integer.parseInt(inv_id));
    	param.put("ID_OUT", Integer.parseInt(outv_id));
    	param.put("LABEL", label);
    	Object query_ret;
		try {
			query_ret = client.execute("g.v(ID_OUT).outE(LABEL).inV().filter{it.id == ID_IN}.id;", param);
		} catch (RexProException e) {
			logger.error("findEdge RexProException for args:" + outv_id + ", " + label + ", " + inv_id);
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			logger.error("findEdge IOException for args:" + outv_id + ", " + label + ", " + inv_id);
			e.printStackTrace();
			return false;
		}
    	List query_ret_list = (List)query_ret;
    	//logger.info("query returned: " + query_ret_list);
    	if(query_ret_list.size() == 0){
    		//logger.info("findEdge found 0 matching edges for name:" + name); //this is too noisy, the invoking function can complain if it wants to...
    		return false;
    	}else if(query_ret_list.size() > 1){
    		logger.warn("findEdge found more than 1 matching edges for args:" + outv_id + ", " + label + ", " + inv_id);
    		return true;
    	}else{
    		return true;
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
    	param.put("ID", Integer.parseInt(id));
    	param.put("KEY", key);
    	param.put("VAL", val);
    	return execute("g.v(ID)[KEY]=VAL;g.commit()", param);
    }
    
    //mergeMethods are derived from ontology definition
    public void alignVertProps(String vertID, Map<String, Object> newProps, Map<String, String> mergeMethods){
    	
    //	System.out.println("vertID = " + vertID);
    //	System.out.println("newProps = " + newProps);
   // 	System.out.println("mergeMethods = " + mergeMethods);
    	
    	Map<String, Object> oldProps = getVertByID(vertID);
    	Iterator<String> k = newProps.keySet().iterator();
		String key;
		while(k.hasNext()){
			key = k.next();
			if(oldProps.containsKey(key)){ //both old & new have this, so check how to merge.
				String mergeMethod = mergeMethods.get(key);
	//			System.out.println("key = " + key + " mergeMethod = " + mergeMethod);
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
    	
  //  	for (int i = 0; i < verts.length(); i++)	{
 //		
  //  		System.out.println("--------->>>>>>" + verts.get(i));
  //  	}
    	
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
   // 		System.out.println("for " + vertName + " = " + mergeMethodsCurrVert);
    	}
    	return mergeMethods;
	}
;
    /*
     * These two methods will generate the following warning in your rexstitan.log (or similar):
     *  WARN  com.thinkaurelius.titan.graphdb.transaction.StandardTitanTx  - Query requires iterating over all vertices [()]. For better performance, use indexes
     * This *should* be the only place that will generate these.  If not, something is wrong.
     */
	public boolean removeAllVertices(){
		//NB: this query is slow enough that connection can time out if the DB starts with many vertices.
		boolean ret = true;
		//delete the known nodes first, to help prevent timeouts.
		Map<String,Object> param;
		Collection<String> ids = vertIDCache.values();
		for(String id : ids){
			param = new HashMap<String,Object>();
			param.put("ID", Integer.parseInt(id));
			try{
				client.execute("g.v(ID).delete();", param);
			}catch(Exception e){
				ret = false;
			}
		}
		try{
			client.execute("g.commit();");
		}catch(Exception e){
			ret = false;
		}
		
		//TODO break this up further, into smaller operations?  (See if timeouts ever still occur.)
		try{
			client.execute("g.V.remove();g.commit();");
		}catch(IOException e){
			logger.warn("connection timeout in removeAllVertices - going to sleep for a while and hope it resolves itself.");
			try {
				Thread.sleep(90000); //in ms.
	         }
	         catch (InterruptedException ie) { 
	             // Restore the interrupted status
	             Thread.currentThread().interrupt();
	         }
			ret = false;
		}catch(Exception e){
			ret = false;
		}
		
		//clear the cache now.
		vertIDCache = new HashMap<String, String>(10000);
		
		return ret;
    }
    /*
    public boolean removeAllEdges(){
		return execute("g.E.each{g.removeVertex(it)};g.commit()");
    }*/

	public Map<String, Map<String, Object>> getConfig (JSONObject vertex)	{
		
		Map<String, Map<String, Object>> property = config.getConfig(vertex.getString("vertexType"));
		
		return property;
	}
	
	public Map<String, String> getIDCache ()	{
		
		return vertIDCache;
	}
	
	public Logger getLogger()	{
		
		return logger;
	}
	
}
