package alignment.alignment_v2;

import alignment.alignment_v2.Constraint;
import alignment.alignment_v2.Constraint.Condition;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.TreeSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InMemoryDBConnection {

	private Logger logger = null;
	
	private Map<String, Map<String, Object>> vertices = null;
	private Map<String, String> vertIDs = null;
	private Map<String, Map<String, Object>> edges = null; //TODO: make/use an Edge class, to store inV, outV, label?  And maybe index that.
	//private Map<String, String> edgeIDs = null; //edges don't have meaningful names.
	private Set<String> indexedVertFields = null; //TODO: not maintaining any indexed fields for now, add later if desired.

	public InMemoryDBConnection(){
		vertices = new HashMap<String, Map<String, Object>>();
		vertIDs = new HashMap<String, String>();
		edges = new HashMap<String, Map<String, Object>>();
		//edgeIDs = new HashMap<String, String>(); //edges don't have meaningful names.
		indexedVertFields = new HashSet();
		//TODO: initialize any indexes.
	}

	public Map<String, Object> getVertByID(String vertID){
		return vertices.get(vertID);
	}

	public Map<String,Object> getVertByName(String vertName) throws Exception{ //TODO: real exception: "invalid state"?
		if(vertName == null || vertName == "")
			return null;
		String id = vertIDs.get(vertName);
		if(id == null)
			return null;
		Map<String, Object> retVal = vertices.get(id);
		if(retVal == null)
			throw new Exception("bad state: known vertex name has no known content.");
		return retVal;
	}

	public String getVertIDByName(String vertName){
		if(vertName == null || vertName == "")
			return null;
		String id = vertIDs.get(vertName);
		return id;
	}
	
	public List<String> getVertIDsByProperty(String propertyName, String propertyValue) {
		List<String> idList = new ArrayList<String>();
		for (String vertId : vertices.keySet()) {
			Map<String, Object> vertex = vertices.get(vertId);
			if (vertex.containsKey(propertyName)) {
				if (vertex.get(propertyName).equals(propertyValue)) {
					idList.add(vertId);
				}
			}	
		}	
		
		return idList;
	}
	
	public List<String> getInVertIDsByRelation(String outVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		if(relation == null || relation.equals("") ){
			throw new Exception("cannot get edge with missing or invlid relation");
		}
		if(outVertID == null || outVertID.equals("") || !vertIDs.containsKey(outVertID)){
			throw new Exception("cannot get edge with missing or invalid outVertID");
		}
		
		List<String> relatedIDs = new LinkedList<String>();
		for(Map<String, Object> currEdge : edges.values()){
			if( ((String)currEdge.get("relation")).equals(relation) ){
				if( ((String)currEdge.get("outVertID")).equals(outVertID) ){
					relatedIDs.add( (String)currEdge.get("inVertID") ); //TODO: check valid state here?
				}
			}
		}
		return relatedIDs;
	}
	
	public List<String> getOutVertIDsByRelation(String inVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		if(relation == null || relation.equals("") ){
			throw new Exception("cannot get edge with missing or invlid relation");
		}
		if(inVertID == null || inVertID.equals("") || !vertIDs.containsKey(inVertID)){
			throw new Exception("cannot get edge with missing or invalid inVertID");
		}
		
		List<String> relatedIDs = new LinkedList<String>();
		for(Map<String, Object> currEdge : edges.values()){
			if( ((String)currEdge.get("relation")).equals(relation) ){
				if( ((String)currEdge.get("inVertID")).equals(inVertID) ){
					relatedIDs.add( (String)currEdge.get("outVertID") ); //TODO: check valid state here?
				}
			}
		}
		return relatedIDs;
	}
	
	public List<String> getVertIDsByRelation(String vertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		if(relation == null || relation.equals("") ){
			throw new Exception("cannot get edge with missing or invlid relation");
		}
		if(vertID == null || vertID.equals("") || !vertIDs.containsKey(vertID)){
			throw new Exception("cannot get edge with missing or invalid inVertID");
		}
		
		List<String> relatedIDs = new LinkedList<String>();
		for(Map<String, Object> currEdge : edges.values()){
			if( ((String)currEdge.get("relation")).equals(relation) ){
				if( ((String)currEdge.get("inVertID")).equals(vertID) || ((String)currEdge.get("outVertID")).equals(vertID)){
					relatedIDs.add( (String)currEdge.get("outVertID") ); //TODO: check valid state here?
				}
			}
		}
		return relatedIDs;
	}
	
	public List<String> getEdgeIDsByVert(String inVertID, String outVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		if(relation == null || relation.equals("") ){
			throw new Exception("cannot add edge with missing or invlid relation");
		}
		if(inVertID == null || inVertID.equals("") || !vertIDs.containsKey(inVertID)){
			throw new Exception("cannot add edge with missing or invalid inVertID");
		}
		if(outVertID == null || outVertID.equals("") || !vertIDs.containsKey(outVertID)){
			throw new Exception("cannot add edge with missing or invalid outVertID");
		}
		
		List<String> edgeIDs = new LinkedList<String>();
		for( String k : edges.keySet() ){
			Map<String, Object> currEdge = edges.get(k);
			if( ((String)currEdge.get("relation")).equals(relation) ){
				if( ((String)currEdge.get("inVertID")).equals(inVertID) ){
					if( ((String)currEdge.get("outVertID")).equals(outVertID) ){
						edgeIDs.add(k);
					}
				}
			}
		}
		return edgeIDs;
	}
	
	public List<String> getVertIDsByConstraints(List<Constraint> constraints) throws Exception{//TODO: real exception: "invalid argument"?
		List<String> matchingIDs = new LinkedList<String>();
		//TODO lookup.
		return matchingIDs;
	}
	
	public Map<String,Object> getEdgeByID(String edgeID){
		return edges.get(edgeID);
	}
	
	
	public Map<String,Object> removeEdgeByID(String edgeID){
		//TODO: update any indices
		return edges.remove(edgeID);
	}
	
	public Map<String,Object> removeVertByID(String vertID) throws Exception{ //TODO: real exception: "invalid state"?
		Object nameObj = vertices.get(vertID).get("name");
		if(nameObj == null || !(nameObj instanceof String) ){
			throw new Exception("bad state: vertex must contain name field");
		}
		
		String name = (String)nameObj;
		vertIDs.remove(name);
		//TODO: update any indices
		return vertices.remove(vertID);
	}
	
	public String addVertex(Map<String, Object> vert) throws Exception{ //TODO: real exception: "invalid argument"?
		Object nameObj = vert.get("name");
		if(nameObj == null || !(nameObj instanceof String) || ((String)nameObj).equals("") ){
			throw new Exception("cannot add vertes with empty name field");
		}//TODO check any other mandatory fields
		
		String name = (String)nameObj;
		if(vertIDs.containsKey(name)){
			removeVertByID(getVertIDByName(name));
		}
		String vertID = String.valueOf( UUID.randomUUID() );
		vertIDs.put(name, vertID);
		vertices.put(vertID, vert);
		//TODO: update any indices
		return vertID;
	}
	
	public String addEdge(String inVertID, String outVertID, String relation) throws Exception{ //TODO: real exception: "invalid argument"?
		if(relation == null || relation.equals("") ){
			throw new Exception("cannot add edge with missing or invlid relation");
		}
		if(inVertID == null || inVertID.equals("") || !vertIDs.containsKey(inVertID)){
			throw new Exception("cannot add edge with missing or invalid inVertID");
		}
		if(outVertID == null || outVertID.equals("") || !vertIDs.containsKey(outVertID)){
			throw new Exception("cannot add edge with missing or invalid outVertID");
		}
		//TODO: check if edge is duplicate??  For now, just add it, duplicates are ok I guess.
		
		Map<String, Object> newEdge = new HashMap<String, Object>();
		newEdge.put("inVertID", inVertID);
		newEdge.put("outVertID", outVertID);
		newEdge.put("relation", relation);
		
		String edgeID = String.valueOf( UUID.randomUUID() );
		edges.put(edgeID, newEdge);
		//TODO: update any indices
		return edgeID;
	}
	
	public void updateVertex(String VertID, Map<String, Object> newVert) throws Exception{ //TODO: real exception: "invalid argument"?
		Map<String, Object> oldVert = vertices.get(VertID);
		if(oldVert == null){
			throw new Exception("invalid vertex ID");
		}
		Object newVertName = newVert.remove("name");
		Object oldVertName = oldVert.get("name");
		if(newVertName != null && !(((String)newVertName).equals((String)oldVertName)) ){
			throw new Exception("cannot update name of existing vertex");
		}
		
		for(String k: newVert.keySet()){
			oldVert.put(k, newVert.get(k));
		}
		//TODO: update any indices
	}
	
	
	private void commit(){
	}
	
	//tries to commit, returns true if success.
	private boolean tryCommit(){
		try{
			commit();
		}catch(Exception e){
			return false;
		}
		return true;
	}
	
	//tries to commit, up to 'limit' times. returns true if success.
	private boolean tryCommit(int limit){
		int count = 0;
		boolean result = false;
		while(!result && count < limit){
			result = tryCommit();
			count += 1;
		}
		return result;
	}

	private void waitFor(int ms){
		try {
			Thread.sleep(ms);
		}
		catch (InterruptedException ie) { 
			// Restore the interrupted status
			Thread.currentThread().interrupt();
		}
	}
	
	private static String getStackTrace(Exception e){
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString();
	}
	
	//see Align class
	public List<Object> jsonArrayToList(JSONArray a){
		List<Object> l = new ArrayList<Object>();
		for(int i=0; i<a.length(); i++){
			l.add(a.get(i));
		}
		return l;
	}
	
	//see Align class	
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

}
