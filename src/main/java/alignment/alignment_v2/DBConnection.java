package alignment.alignment_v2;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.BaseConfiguration;
import org.apache.commons.configuration.Configuration;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thinkaurelius.titan.core.TitanGraph;
import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;

public class DBConnection {

	RexsterClient client = null;
	private Logger logger = null;
	private Map<String, String> vertIDCache = null;

	public static RexsterClient getDefaultClient(){
		RexsterClient client = null;
		Logger logger = LoggerFactory.getLogger(Align.class);
		
		Configuration configOpts = ConfigFileLoader.configFromFile("rexster-config/rexster-default-config");
		
		logger.info("connecting to DB...");
		
		try {
			client = RexsterClientFactory.open(configOpts); //this just throws "Exception."  bummer.
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return client;
	}

	public static RexsterClient getTestClient(){
		RexsterClient client = null;
		Logger logger = LoggerFactory.getLogger(Align.class);
		
		Configuration configOpts = ConfigFileLoader.configFromFile("rexster-config/rexster-test-config");

		logger.info("connecting to Test DB...");
		
		try{
			client = RexsterClientFactory.open(configOpts); //this just throws "Exception."  bummer.
		}catch(Exception e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return client;
	}

	public static void closeClient(RexsterClient client){
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

	public DBConnection(){
		this(getDefaultClient());
	}

	public DBConnection(RexsterClient c){
		//TODO
		logger = LoggerFactory.getLogger(Align.class);
		vertIDCache = new HashMap<String, String>(10000);
		client = c;
	}

	public void createIndices(){
		try {

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

	public void addVertexFromJSON(JSONObject vert){
		String name = vert.optString("name");
		//System.out.println("vertex name is: " + name);
		String id = vert.optString("_id");
		//System.out.println("vertex id is: " + id);
		if(name == null || name == ""){ 
			vert.put("name", id);
		}
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("VERT_PROPS", vert);
		execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null)", param);
	}

	public void addEdgeFromJSON(JSONObject edge){
		Map<String, Object> param = new HashMap<String, Object>();

		//System.out.println("edge outV is " + edge.getString("_outV"));
		String outv_id = findVertId(edge.getString("_outV"));
		String inv_id = findVertId(edge.getString("_inV"));
		String edgeName = edge.getString("_id");
		//System.out.println("ID = " + edgeName);
		//String edgeID = findEdgeId(edgeName);
		if(outv_id == null){
			logger.error("Could not find out_v for edge: " + edge);
			//continue;
		}
		if(inv_id == null){
			logger.error("Could not find in_v for edge: " + edge);
			//continue;
		}
		String label = edge.optString("_label");
		if(edgeExists(inv_id, outv_id, label)){
			//TODO need to merge edge props for this case, like verts above...
			logger.debug("Attempted to add edge with duplicate name.  ignoring ...");
			//continue;
		}
		param.put("ID_OUT", Integer.parseInt(outv_id));
		param.put("ID_IN", Integer.parseInt(inv_id));
		param.put("LABEL", label);
		//build your param map obj
		Map<String, Object> props = new HashMap<String, Object>();
		props.put("edgeName", edgeName);
		edge.remove("_inv");
		edge.remove("_outv");
		edge.remove("_id");
		Iterator<String> k = edge.keys();
		String key;
		while(k.hasNext()){
			key = k.next();
			props.put(key, edge.get(key));
			//	System.out.println(key);
		}
		param.put("EDGE_PROPS", props);
		//and now finally add edge to graph
		execute("g.addEdge(g.v(ID_OUT),g.v(ID_IN),LABEL,EDGE_PROPS)", param);
	}

	public void commit(){
		execute("g.commit()");
	}

	//TODO make private
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

	//should only use in tests...
	public RexsterClient getClient(){
		return client;
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
			logger.info("findVert found 0 matching verts for name:" + name); //this is too noisy, the invoking function can complain if it wants to...
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

	public List findAllVertsByType(String vertexType) throws IOException, RexProException{
		if(vertexType == null || vertexType == "")
			return null;

		Map<String, Object> param = new HashMap<String, Object>();
		param.put("TYPE", vertexType);
		Object query_ret = client.execute("g.query().has(\"vertexType\",TYPE).vertices().toList();", param);
		List<Map<String,Object>> query_ret_list = (List<Map<String,Object>>)query_ret;

		if(query_ret_list.size() == 0){
			logger.warn("findAllVertsByType found 0 matching verts for type:" + vertexType);
			return null;
		}
		return query_ret_list;
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

	public boolean edgeExists(String inv_id, String outv_id, String label) {
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
    public boolean removeAllEdges(RexsterClient client){
		return execute("g.E.each{g.removeVertex(it)};g.commit()");
    }*/



}
