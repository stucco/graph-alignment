package alignment.alignment_v2;

import gov.ornl.stucco.DBClient.Constraint;
import gov.ornl.stucco.DBClient.DBConnection;
import gov.ornl.stucco.DBClient.Constraint.Condition;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.json.*;

import com.tinkerpop.rexster.client.RexProException;
import com.tinkerpop.rexster.client.RexsterClient;

/**
 * Connects to Graph DB, aligns and adds new incoming graph data, provides some misc. utility functions.
 *
 */
public class Align 
{

	private static final boolean SEARCH_FOR_DUPLICATES = false;
	private static final boolean ALIGN_VERT_PROPS = false;
	private RexsterClient client = null;
	private Logger logger = null;
	private ConfigFileLoader config = null;
	private DBConnection connection = null;

	public Align(){
		this(new DBConnection());
	}

	public Align(DBConnection c) {
		this.connection = c;
		client = connection.getClient(); //TODO shouldn't need this...

		logger = LoggerFactory.getLogger(Align.class);

		//loading configuration file into HashMap
		config = new ConfigFileLoader();

		connection.createIndices();
	}

	@Override
	protected void finalize() throws Throwable {
		DBConnection.closeClient(this.client);
		super.finalize();
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
		List<JSONObject> verts = new ArrayList<JSONObject>();
		List<JSONObject> edges = new ArrayList<JSONObject>();
		try{
			JSONObject graphson = new JSONObject(newGraphSection);
			JSONArray json_verts = graphson.optJSONArray("vertices");

			if(json_verts != null){			//if there are vertices...
				int vertCount = json_verts.length();
				for(int i=0; i<vertCount; i++){		//add each one to verts list
					JSONObject vert = (JSONObject)json_verts.get(i);
					if(!vert.has("name"))
						vert.put("name", vert.get("_id"));	//add "name" field equals its ID if needed
					verts.add(vert);	//place vertex json object
				}
			}
			//...and likewise for edges
			JSONArray json_edges = graphson.optJSONArray("edges");
			if(json_edges != null){
				int edgeCount = json_edges.length();
				for(int i=0; i<edgeCount; i++){
					JSONObject edge = (JSONObject)json_edges.get(i);
					edges.add(edge);
				}
			}
		}catch(Exception e){ 
			//we want *any* graphson problems to end up here
			//being noisy when these fail is probably ok, we shouldn't really ever fail here except when testing, etc.
			logger.error("Error parsing GraphSON in load()!");
			logger.error("The graphson was: " + newGraphSection);
			logger.error("Exception!",e);
			return false;
		}

		//for *vertices*, you have a json object that you can load.
		int i=0;
		for(JSONObject vert : verts){
			String vert_name = vert.getString("name");
			String vert_id = vert.optString("_id");
			if(vert_name == null || vert_name == ""){
				vert_name = vert_id;
				vert.put("name", vert_name);
			}
			boolean new_vert = false;
			String otherVertID = connection.findVertId(vert_name);
			new_vert = (otherVertID == null);
			Map<String, Object> vertMap = null;
			if(!new_vert && SEARCH_FOR_DUPLICATES){
				vertMap = jsonVertToMap(vert);
				otherVertID = findDuplicateVertex(vertMap);
				new_vert = (otherVertID == null);
			}
			if(new_vert){ //only add new...
				String type = null;
				type = (String)vert.opt("vertexType");
				if(type.equals("IP")){ 
					//if its an ip vert, and doesn't have an ip int, just add that here.
					//TODO: the extractors should really be doing this, but some aren't
					long ipInt = vert.optLong("ipInt");
					if(ipInt == 0){
						String ipString = vert.getString("name");
						ipInt = getIpInt(ipString);
						vert.put("ipInt", ipInt);
					}
				}
				vertMap = jsonVertToMap(vert);
				//connection.addVertexFromJSON(vert);
				connection.addVertexFromMap(vertMap);
				connection.commit();
				List<JSONObject> newEdges = findNewEdges(vert);
				for(JSONObject edge: newEdges){
					edges.add(edge);
				}
			}else{
				if(ALIGN_VERT_PROPS){
					if(vertMap == null) vertMap = jsonVertToMap(vert); //might have this from above already, or might not
					alignVertProps(otherVertID, vertMap);
				}
				else{
					logger.debug("Attempted to add vertex when duplicate exists.  ALIGN_VERT_PROPS is false, so ignoring new vert...");
				}
			}
			i++;
			if(i%150 == 0){ //TODO revisit this 
				connection.commit();//only commit periodically, so that operations can be combined by Titan.
			}
		}
		connection.commit(); //make sure all verts are committed before proceeding.

		Map<String, Object> param = new HashMap<String, Object>();
		//for *edges*, you can't really do that, so find IDs and build a map of needed properties instead.
		i=0;
		for(JSONObject edge : edges){
			String outv_id = connection.findVertId(edge.getString("_outV"));
			String inv_id = connection.findVertId(edge.getString("_inV"));
			String edgeName = edge.getString("_id");
			//String edgeID = findEdgeId(edgeName);
			if(outv_id == null){
				logger.error("Could not find out_v for edge: " + edge);
				continue;
			}
			if(inv_id == null){
				logger.error("Could not find in_v for edge: " + edge);
				continue;
			}
			String label = edge.optString("_label");
			if(connection.edgeExists(inv_id, outv_id, label)){
				//TODO need to merge edge props for this case, like verts above...
				logger.debug("Attempted to add edge with duplicate name.  ignoring ...");
				continue;
			}
			connection.addEdgeFromJSON(edge);
			i++;
			if(i%150 == 0){ //TODO revisit this
				connection.commit();//only commit periodically, so that operations can be combined by Titan.
			}
		}
		connection.commit(); //make sure all edges are committed also.

		return true;//TODO what if some execute()s pass and some fail?
	}

	private List<JSONObject> findNewEdges(JSONObject vert) {
		List<JSONObject> edges = new ArrayList<JSONObject>();
		
		String vert_name = vert.getString("name");
		String type = null;
		type = (String)vert.opt("vertexType");
		if(type == null){
			logger.warn("no vertex type specified for vertex:" + vert.toString());
		}else{
			if(type.equals("addressRange")){
				long endIpInt = vert.optLong("endIPInt");
				long startIpInt = vert.optLong("startIPInt");
				if( endIpInt !=0 && startIpInt != 0){
					List<Constraint> constraints = new ArrayList<Constraint>();
					Constraint c = new Constraint("vertexType", Condition.eq, "IP");
					constraints.add(c);
					c = new Constraint("ipInt", Condition.lte, endIpInt);
					constraints.add(c);
					c = new Constraint("ipInt", Condition.gte, startIpInt);
					constraints.add(c);
					List<Map<String,Object>> matches = null;
					try {
						matches = connection.findAllVertsWithProps(constraints);
					} catch (IOException e) {
						logger.error("Exception!",e);
					} catch (RexProException e) {
						logger.error("Exception!",e);
					}
					if(matches != null){
						for(Map<String,Object> match : matches){
							Map<String,Object> currMatchProps = (Map<String,Object>)match.get("_properties");
							String inv = vert_name;
							String outv = (String)currMatchProps.get("name");
							JSONObject edge = new JSONObject();
							edge.put("_type", "edge");
							edge.put("_id", outv + "_inAddressRange_" + inv);
							edge.put("_label", "inAddressRange");
							edge.put("_inV", inv);
							edge.put("_outV", outv);
							edge.put("inVType", "addressRange");
							edge.put("outVType", "IP");
							edges.add(edge);
						}
					}
				}else{
					logger.warn("address range vert did not have int addresses: " + vert.toString());
				}
			}else if(type.equals("IP")){
				List<Constraint> constraints = new ArrayList<Constraint>();
				Constraint c = new Constraint("vertexType", Condition.eq, "addressRange");
				constraints.add(c);
				c = new Constraint("endIPInt", Condition.gte, vert.getLong("ipInt"));
				constraints.add(c);
				c = new Constraint("startIPInt", Condition.lte, vert.getLong("ipInt"));
				constraints.add(c);
				List<Map<String,Object>> matches = null;
				try {
					matches = connection.findAllVertsWithProps(constraints);
				} catch (IOException e) {
					logger.error("Exception!",e);
				} catch (RexProException e) {
					logger.error("Exception!",e);
				}
				if(matches != null){
					for(Map<String,Object> match : matches){
						Map<String,Object> currMatchProps = (Map<String,Object>)match.get("_properties");
						String inv = (String)currMatchProps.get("name");
						String outv = vert_name;
						JSONObject edge = new JSONObject();
						edge.put("_type", "edge");
						edge.put("_id", outv + "_inAddressRange_" + inv);
						edge.put("_label", "inAddressRange");
						edge.put("_inV", inv);
						edge.put("_outV", outv);
						edge.put("inVType", "addressRange");
						edge.put("outVType", "IP");
						edges.add(edge);
					}
				}
			}
		}
		return edges;
	}

	public void alignVertProps(String vertID, Map<String, Object> newProps){
		String type = (String)newProps.get("vertexType");
		Map<String, Map<String, Object>> mergeMethods = getVertexConfig(type);
		alignVertProps(vertID, newProps, mergeMethods);
	}
	
	//mergeMethods are derived from ontology definition
	public void alignVertProps(String vertID, Map<String, Object> newProps, Map<String, Map<String, Object>> vertConfig){

		//	System.out.println("vertID = " + vertID);
		//	System.out.println("newProps = " + newProps);
		// 	System.out.println("mergeMethods = " + mergeMethods);

		Map<String, Object> oldProps = connection.getVertByID(vertID);
		Iterator<String> k = newProps.keySet().iterator();
		String key;
		while(k.hasNext()){
			key = k.next();
			if(oldProps.containsKey(key)){ //both old & new have this, so check how to merge.
				String mergeMethod = null;
				try{
					mergeMethod = (String) vertConfig.get(key).get("resolutionFunction");
				}catch(NullPointerException e){
					mergeMethod = null; //this will happen if 'key' isn't in the vertConfig map.
					if(key != "timeStamp" && key != "score"){
						logger.warn("no config info found for property: " + key);
					}
				}
				//			System.out.println("key = " + key + " mergeMethod = " + mergeMethod);
				if(key == "timeStamp" || key == "score"){
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
					Object oldVal = oldProps.get("timeStamp");
					long oldTime = -1;
					if(oldVal instanceof String)
						oldTime = Integer.parseInt((String)oldProps.get("timeStamp"));
					else if(oldVal instanceof Long)
						oldTime = (Long)oldVal;
					//TODO else warn?
					long newTime = (Long)newProps.get("timeStamp");
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
		connection.updateVert(vertID, oldProps);
	}

	public List<Object> jsonArrayToList(JSONArray a){
		List<Object> l = new ArrayList<Object>();
		for(int i=0; i<a.length(); i++){
			l.add(a.get(i));
		}
		return l;
	}

	public Map<String, Object> jsonVertToMap(JSONObject v){
		Map<String, Object> vert = new HashMap<String, Object>();
		for(Object k : v.keySet()){
			String key = (String) k;
			Object value = v.get(key);
			if(value instanceof JSONArray){
				value = jsonArrayToList((JSONArray)value);
			}
			else if(value instanceof JSONObject){
				logger.warn("jsonVertToMap: unexpected property type: JSONObject for property " + key + "\n" + v);
			}
			vert.put(key, value);
		}
		return vert;
	}
	
	//only public for tests
	public String findDuplicateVertex(Map<String, Object> vertex)	{
		//TODO populate threshold
		double threshold = 0.75;

		Map<String, Object> vertexProps = (Map<String, Object>)(vertex.get("_properties"));
		String vertexType = (String)(vertexProps.get("vertexType"));
		//TODO check vertexType: for some types, we never want to search in this way (eg. flows.)
		
		List<Map<String,Object>> candidateVerts = findCandidateMatches(vertex);
		Map<String, Double> candidateScores = new HashMap<String, Double>();
		Map<String, Object> candidateVertex = null;

		double bestScore = 0.0;
		String bestID = null;

		Map<String, Map<String, Object>> configProperties = getVertexConfig(vertexType);

		for(int i = 0; i < candidateVerts.size(); i++){
			candidateVertex = candidateVerts.get(i);
			String id = (String)candidateVertex.get("_id");
			double score = Compare.compareVertices(vertex, candidateVertex, configProperties);
			logger.info("Found score of " + score + " for id " + id);
			if(score >= threshold){
				candidateScores.put(id, score);
				if(score > bestScore){
					bestID = id;
					bestScore = score;
				}
			}
		}
		return bestID;
	}


	public List<Map<String,Object>> findCandidateMatches(Map<String, Object> vertex) {
		List<Map<String,Object>> results = new ArrayList<Map<String,Object>>();

		Map<String, Object> vertexProps = (Map<String, Object>)(vertex.get("_properties"));
		String vertType = (String)(vertexProps.get("vertexType"));
		try {
			results = connection.findAllVertsByType(vertType);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (RexProException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//logger.info("candidate matches are: " + results);
		return results;
	}

	//Unused
	public Map<String, Map<String, Object>> getVertexConfig (JSONObject vertex)	{
		return getVertexConfig(vertex.getString("vertexType"));
	}

	public Map<String, Map<String, Object>> getVertexConfig (String vertexType)	{
		Map<String, Map<String, Object>> property = config.getVertexConfig(vertexType);
		return property;
	}

	//TODO only public for tests
	public long getIpInt(String ipString) {
		long retAddr = 0;
		try {
			InetAddress addr = InetAddress.getByName(ipString);
			for (byte b: addr.getAddress()){  
				retAddr = (retAddr << 8) | (b & 0xFF);
			}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return retAddr;
	}

}
