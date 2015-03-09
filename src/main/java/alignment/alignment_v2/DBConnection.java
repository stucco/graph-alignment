package alignment.alignment_v2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.configuration.BaseConfiguration;
import org.apache.commons.configuration.Configuration;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import alignment.alignment_v2.Constraint.Condition;

import com.thinkaurelius.titan.core.TitanGraph;
import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;
import com.tinkerpop.blueprints.*;

public class DBConnection {

	private RexsterClient client = null;
	private Logger logger = null;
	private Map<String, String> vertIDCache = null;
	private String dbType = null;

	public static RexsterClient createClient(Configuration configOpts){
		return createClient(configOpts, 0);
	}

	/*
	 * Note that connectionWaitTime is in seconds
	 */
	public static RexsterClient createClient(Configuration configOpts, int connectionWaitTime){
		RexsterClient client = null;
		Logger logger = LoggerFactory.getLogger(Align.class);

		logger.info("connecting to DB...");

		try {
			client = RexsterClientFactory.open(configOpts); //this just throws "Exception."  bummer.
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//if wait time given, then wait that long, so the connection can set up.  (Mostly needed for travis-ci tests)
		if(connectionWaitTime > 0){
			try {
				logger.info( "waiting for " + connectionWaitTime + " seconds for connection to establish..." );
				Thread.sleep(connectionWaitTime*1000); //in ms.
			}
			catch (InterruptedException ie) { 
				// Restore the interrupted status
				Thread.currentThread().interrupt();
			}
		}

		return client;
	}

	public static Configuration getDefaultConfig(){
		Logger logger = LoggerFactory.getLogger(Align.class);
		logger.info("Loading default DB Config...");
		Configuration configOpts = ConfigFileLoader.configFromFile("rexster-default-config.yml");
		return configOpts;
	}

	public static Configuration getTestConfig(){
		Logger logger = LoggerFactory.getLogger(Align.class);
		logger.info("Loading test DB Config...");
		Configuration configOpts = ConfigFileLoader.configFromFile("rexster-test-config.yml");
		return configOpts;
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
		this(createClient(getDefaultConfig()));
	}

	public DBConnection(RexsterClient c){
		//TODO
		logger = LoggerFactory.getLogger(Align.class);
		vertIDCache = new HashMap<String, String>(10000);
		client = c;
	}

	private String getDBType(){
		if(this.dbType == null){
			String type = null;
			try{
				type = client.execute("g.getClass()").get(0).toString();
			}catch(Exception e){
				logger.error("Could not find graph type!",e);
			}
			if( type.equals("class com.tinkerpop.blueprints.impls.tg.TinkerGraph") ){
				this.dbType = "TinkerGraph";
			}else if( type.equals("class com.thinkaurelius.titan.graphdb.database.StandardTitanGraph") ){
				this.dbType = "TitanGraph";
			}else{
				logger.warn("Could not find graph type, or unknown type!  Assuming it is Titan...");
				this.dbType = "TitanGraph";
			}
		}
		return this.dbType;
	}


	public void createIndices(){
		String graphType = getDBType();
		if( graphType.equals("TinkerGraph") ){
			createTinkerGraphIndices();
		}else if( graphType.equals("TitanGraph") ){
			createTitanIndices();
		}else{
			logger.warn("unknown graph type!  Assuming it is Titan...");
			createTitanIndices();
		}
	}


	private void createTinkerGraphIndices(){
		List<String> currentIndices = new ArrayList<String>();
		try {
			currentIndices = client.execute("g.getIndexedKeys(Vertex.class)");
		} catch (Exception e) { 
			//this.client = null;
			logger.error("problem getting indexed keys, assuming there were none...");
			logger.error("Exception was: ",e);
		}
		logger.info( "found vertex indices: " + currentIndices );
		try {
			if(!currentIndices.contains("name")){
				logger.info("'name' key index not found, creating ...");
				client.execute("g.createKeyIndex('name', Vertex.class);g");
			}
			if(!currentIndices.contains("vertexType")){
				logger.info("'vertexType' key index not found, creating ...");
				client.execute("g.createKeyIndex('vertexType', Vertex.class);g");
			}
			if(!currentIndices.contains("ipInt")){
				logger.info("'ipInt' key index not found, creating ...");
				client.execute("g.createKeyIndex('ipInt', Vertex.class);g");
			}
			if(!currentIndices.contains("startIPInt")){
				logger.info("'startIPInt' key index not found, creating ...");
				client.execute("g.createKeyIndex('startIPInt', Vertex.class);g");
			}
			if(!currentIndices.contains("endIPInt")){
				logger.info("'endIPInt' key index not found, creating ...");
				client.execute("g.createKeyIndex('endIPInt', Vertex.class);g");
			}
		} catch (RexProException e) {
			logger.error("Exception was: ",e);
		} catch (IOException e) {
			logger.error("Exception was: ",e);
		}
	}

	private void createTitanIndices(){
		List currentIndices = null;
		try {
			//configure vert indices needed
			//List currentIndices = client.execute("g.getManagementSystem().getGraphIndexes(Vertex.class)");
			currentIndices = client.execute("g.getIndexedKeys(Vertex.class)");
		} catch (Exception e) { 
			//this.client = null;
			logger.error("problem getting indexed keys, assuming there were none...");
			logger.error("Exception was: ",e);
		}
		logger.info( "found vertex indices: " + currentIndices );
		try{
			//		System.out.println("currentIndices = " + currentIndices +  " " + "name");
			if(currentIndices == null || !currentIndices.contains("name")){
				List names = client.execute("mgmt = g.getManagementSystem();mgmt.getPropertyKey(\"name\");");
				//logger.info("name found: ", names.get(0));
				if(names.get(0) == null){
					logger.info("'name' variable and index not found, creating var and index...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "name = mgmt.makePropertyKey(\"name\").dataType(String.class).make();"
							+ "mgmt.buildIndex(\"byName\",Vertex.class).addKey(name).unique().buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}else{
					logger.info("'name' was found, but not indexed.  creating index...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "name = mgmt.getPropertyKey(\"name\");"
							+ "mgmt.buildIndex(\"byName\",Vertex.class).addKey(name).unique().buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}
			}
			if(currentIndices == null || !currentIndices.contains("vertexType")){
				List names = client.execute("mgmt = g.getManagementSystem();mgmt.getPropertyKey(\"vertexType\");");
				//logger.info("vertexType found: ", names.get(0));
				if(names.get(0) == null){
					logger.info("'vertexType' variable and index not found, creating var and index...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "vertexType = mgmt.makePropertyKey(\"vertexType\").dataType(String.class).make();"
							+ "mgmt.buildIndex(\"byVertexType\",Vertex.class).addKey(vertexType).buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}else{
					logger.info("'vertexType' was found, but not indexed.  creating index...");
					client.execute("mgmt = g.getManagementSystem();"
							+ "vertexType = mgmt.getPropertyKey(\"vertexType\");"
							+ "mgmt.buildIndex(\"byVertexType\",Vertex.class).addKey(vertexType).buildCompositeIndex();"
							+ "mgmt.commit();g;");
				}
			}
			/*
			if(!currentIndices.contains("name") || !currentIndices.contains("vertexType")){
				logger.info("name or vertexType index not found, creating combined index...");
				client.execute("mgmt = g.getManagementSystem();"
						+ "name = mgmt.getPropertyKey(\"name\");"
						+ "vertexType = mgmt.getPropertyKey(\"vertexType\");"
						+ "mgmt.buildIndex(\"byNameAndVertexType\",Vertex.class).addKey(name).addKey(vertexType).unique().buildCompositeIndex();"
						+ "mgmt.commit();g;"); //TODO: not convinced that this (new) index really works, need to test further.  but it's currently unused, so leaving as-is for now.
			}*/
			commit();
			logger.info("Connection is good!");
		}catch(Exception e){
			logger.warn("could not configure missing vertex indices!", e);
			//NB: this is (typically) non-fatal.  Multiple workers can attempt to create the indices at the same time, and some will just fail in this way.
			//TODO: these need to either be created in one thread only, or else use proper locking.
			//this.client = null;
			//logger.error("Connection is unusable!");
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


	}

	public void addVertexFromJSON(JSONObject vert){
		String graphType = getDBType();
		String name = vert.optString("name");
		//System.out.println("vertex name is: " + name);
		String id = vert.optString("_id");
		//System.out.println("vertex id is: " + id);
		if(name == null || name == ""){ 
			name = id;
			vert.put("name", name);
		}
		vert.remove("_id"); //Some graph servers will ignore this ID, some won't.  Just remove them so it's consistent.
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("VERT_PROPS", vert);
		try {
			Long newID = null;
			if(graphType == "TitanGraph")
				newID = (Long)client.execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);v.getId()", param).get(0);
			if(graphType == "TinkerGraph")
				newID = Long.parseLong((String)client.execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);v.getId()", param).get(0));
			//System.out.println("new ID is: " + newID);
			vertIDCache.put(name, newID.toString());
		} catch (RexProException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void addVertexFromMap(Map vert){
		String graphType = getDBType();
		String name = (String)vert.get("name");
		//System.out.println("vertex name is: " + name);
		String id = (String)vert.get("_id");
		//System.out.println("vertex id is: " + id);
		if(name == null || name == ""){
			name = id;
			vert.put("name", name);
		}
		vert.remove("_id"); //Some graph servers will ignore this ID, some won't.  Just remove them so it's consistent.
		Map<String, Object> param = new HashMap<String, Object>();
		param.put("VERT_PROPS", vert);
		try {
			Long newID = null;
			if(graphType == "TitanGraph")
				newID = (Long)client.execute("v = g.addVertex(null, VERT_PROPS);v.getId();", param).get(0);
				//newID = (Long)client.execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);v.getId()", param).get(0);
			if(graphType == "TinkerGraph")
				newID = Long.parseLong((String)client.execute("v = g.addVertex(null, VERT_PROPS);v.getId();", param).get(0));
				//newID = Long.parseLong((String)client.execute("v = GraphSONUtility.vertexFromJson(VERT_PROPS, new GraphElementFactory(g), GraphSONMode.NORMAL, null);v.getId()", param).get(0));
			//System.out.println("new ID is: " + newID);
			vertIDCache.put(name, newID.toString());
		} catch (RexProException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
		String graphType = getDBType();
		if(graphType != "TinkerGraph")
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

	public List<Map<String,Object>> findAllVertsByType(String vertexType) throws IOException, RexProException{
		if(vertexType == null || vertexType == "")
			return null;

		Map<String, Object> properties = new HashMap<String, Object>();
		List<Constraint> l = new ArrayList<Constraint>();
		Constraint c = new Constraint("vertexType", Condition.eq, vertexType);
		l.add(c);
		List<Map<String,Object>> query_ret_list = findAllVertsWithProps(l);

		if(query_ret_list.size() == 0){
			logger.warn("findAllVertsByType found 0 matching verts for type:" + vertexType);
			return null;
		}
		return query_ret_list;
	}


	public List<Map<String,Object>> findAllVertsWithProps(List<Constraint> constraints) throws IOException, RexProException{
		if(constraints == null || constraints.size() == 0)
			return null;

		Map<String, Object> param = new HashMap<String, Object>();
		//String query = "g.query()";
		String query = "g.V";
		for(int i=0; i<constraints.size(); i++){
			Constraint c = constraints.get(i);
			String cond = c.condString(c.cond);
			String key = c.prop.toUpperCase()+i;
			param.put(key, c.val);
			query += ".has(\"" + c.prop + "\"," + cond + "," + key + ")";
		}
		//query += ".vertices().toList();";
		query += ";";
		Object query_ret = client.execute(query, param);
		List<Map<String,Object>> query_ret_list = (List<Map<String,Object>>)query_ret;

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
		param.put("ID_OUT", Integer.parseInt(outv_id));
		param.put("LABEL", label);
		Object query_ret;
		try {
			query_ret = client.execute("g.v(ID_OUT).outE(LABEL).inV();", param);
		} catch (RexProException e) {
			logger.error("edgeExists RexProException for args:" + outv_id + ", " + label + ", " + inv_id);
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			logger.error("edgeExists IOException for args:" + outv_id + ", " + label + ", " + inv_id);
			e.printStackTrace();
			return false;
		}
		List<Map<String, Object>> query_ret_list = (List<Map<String, Object>>)query_ret;
		//logger.info("query returned: " + query_ret_list);
		for(Map<String, Object> item : query_ret_list){
			if(Integer.parseInt(inv_id) == Integer.parseInt((String)item.get("_id")))
				return true;
		}
		//logger.info("matching edge not found");
		return false;
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
		boolean ret = execute("g.v(ID)[KEY]=VAL", param);
		commit();
		return ret;
	}

	/*
	 * Only use in tests.
	 */
	public boolean removeCachedVertices(){
		//NB: this query is slow enough that connection can time out if the DB starts with many vertices.

		if(vertIDCache.isEmpty())
			return true;

		boolean ret = true;
		//delete the known nodes first, to help prevent timeouts.
		Map<String,Object> param;
		Collection<String> ids = vertIDCache.values();
		for(String id : ids){
			param = new HashMap<String,Object>();
			param.put("ID", Integer.parseInt(id));
			try{
				client.execute("g.v(ID).remove();g", param);
			}catch(Exception e){
				e.printStackTrace();
				ret = false;
			}
		}
		try{
			commit();
		}catch(Exception e){
			e.printStackTrace();
			ret = false;
		}

		//clear the cache now.
		vertIDCache = new HashMap<String, String>(10000);

		return ret;

	}

	/*
	 * Only use in tests.
	 */
	public boolean removeAllVertices(){
		//NB: this query is slow enough that connection can time out if the DB starts with many vertices.
		boolean ret = removeCachedVertices();
		try{
			client.execute("g.v().remove();g");
		}catch(Exception e){
			e.printStackTrace();
			ret = false;
		}
		try{
			commit();
		}catch(Exception e){
			e.printStackTrace();
			ret = false;
		}
		return ret;
	}

	/*
    public boolean removeAllEdges(RexsterClient client){
		return execute("g.E.each{g.removeVertex(it)};g.commit()");
    }*/



}
