package alignment.alignment_v2;

import java.io.IOException;
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


		//for *vertices*, you have a json object that you can load.
		for(int i=0; i<verts.length; i++){
			//System.out.println(verts[i]);
			String vert_name = verts[i].getString("name");
			boolean new_vert = false;
			new_vert = (connection.findVertId(vert_name) == null);
			if(new_vert){ //only add new...
				connection.addVertexFromJSON(verts[i]);
			}else{
				//TODO need to call alignVertProps() for this case, which means we need to make a mergeMethods obj
				logger.debug("Attempted to add vertex with duplicate name.  ignoring ...");
			}
			if(i%150 == 0){
				connection.commit();//only commit periodically, so that operations can be combined by Titan.
			}
		}
		connection.commit(); //make sure all verts are committed before proceeding.

		Map<String, Object> param = new HashMap<String, Object>();
		//for *edges*, you can't really do that, so find IDs and build a map of needed properties instead.
		for(int i=0; i<edges.length; i++){
			String outv_id = connection.findVertId(edges[i].getString("_outV"));
			String inv_id = connection.findVertId(edges[i].getString("_inV"));
			String edgeName = edges[i].getString("_id");
			//System.out.println("ID = " + edgeName);
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
			if(connection.edgeExists(inv_id, outv_id, label)){
				//TODO need to merge edge props for this case, like verts above...
				logger.debug("Attempted to add edge with duplicate name.  ignoring ...");
				continue;
			}
			connection.addEdgeFromJSON(edges[i]);
			if(i%150 == 0){
				connection.commit();//only commit periodically, so that operations can be combined by Titan.
			}
		}
		connection.commit(); //make sure all edges are committed also.

		//System.out.println("size of cacheIDCache = " + vertIDCache.size());

		return true;//TODO what if some execute()s pass and some fail?
	}




	//mergeMethods are derived from ontology definition
	public void alignVertProps(String vertID, Map<String, Object> newProps, Map<String, String> mergeMethods){

		//	System.out.println("vertID = " + vertID);
		//	System.out.println("newProps = " + newProps);
		// 	System.out.println("mergeMethods = " + mergeMethods);

		Map<String, Object> oldProps = connection.getVertByID(vertID);
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
		connection.updateVert(vertID, oldProps);
	}

	//only needs to be public for testing, will probably make private later.
	//returns a map of prop names to merge methods, for each vert name
	//NB: old method, now uses a config file.  may revisit.
	/*
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
	 */


	//only public for tests
	public String findDuplicateVertex(Map<String, Object> vertex)	{
		//TODO populate threshold
		double threshold = 0.75;

		List<Map<String,Object>> candidateVerts = findCandidateMatches(vertex);
		Map<String, Double> candidateScores = new HashMap<String, Double>();
		Map<String, Object> candidateVertex = null;

		double bestScore = 0.0;
		String bestID = null;

		for(int i = 0; i < candidateVerts.size(); i++){
			candidateVertex = candidateVerts.get(i);
			String id = (String)candidateVertex.get("_id");
			double score = Compare.compareVertices(vertex, candidateVertex);
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

		String vertType = (String)vertex.get("vertexType");
		try {
			results = connection.findAllVertsByType(vertType);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (RexProException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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


}
