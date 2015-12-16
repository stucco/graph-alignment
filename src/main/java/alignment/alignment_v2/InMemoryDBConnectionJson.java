package alignment.alignment_v2;

import alignment.alignment_v2.Constraint;
import alignment.alignment_v2.Constraint.Condition;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

public class InMemoryDBConnectionJson {

	private InMemoryDBConnection connect = null;

	public InMemoryDBConnectionJson(){
		connect = new InMemoryDBConnection();
	}

	public JSONObject getVertByID(String vertID){
		return new JSONObject(connect.getVertByID(vertID));
	}

	public JSONObject getVertByName(String vertName) throws Exception{ //TODO: real exception: "invalid state"?
		return new JSONObject(connect.getVertByName(vertName));
	}

	public String getVertIDByName(String vertName){
		return connect.getVertIDByName(vertName);
	}
	
	public List<String> getVertIDsByProperty(String propertyName, String propertyValue) {
		return connect.getVertIDsByProperty(propertyName, propertyValue);
	}
	
	public List<String> getInVertIDsByRelation(String outVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		return connect.getInVertIDsByRelation(outVertID, relation);
	}
	
	public List<String> getOutVertIDsByRelation(String inVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		return connect.getOutVertIDsByRelation(inVertID, relation);
	}
	
	public List<String> getVertIDsByRelation(String vertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		return connect.getVertIDsByRelation(vertID, relation);
	}
	
	public List<String> getEdgeIDsByVert(String inVertID, String outVertID, String relation) throws Exception{//TODO: real exception: "invalid argument"?
		return connect.getEdgeIDsByVert(inVertID, outVertID, relation);
	}
	public List<String> getVertIDsByConstraints(List<Constraint> constraints) throws Exception{//TODO: real exception: "invalid argument"?
		return connect.getVertIDsByConstraints(constraints);
	}
	
	public JSONObject getEdgeByID(String edgeID){
		return new JSONObject(connect.getEdgeByID(edgeID));
	}
	
	
	public JSONObject removeEdgeByID(String edgeID){
		return new JSONObject (connect.removeEdgeByID(edgeID));
	}
	
	public JSONObject removeVertByID(String vertID) throws Exception{ //TODO: real exception: "invalid state"?
		return new JSONObject(connect.removeVertByID(vertID));
	}
	
	public String addVertex(JSONObject vertex) throws Exception{ //TODO: real exception: "invalid argument"?
		Map<String, Object> vert = new HashMap<String, Object>();
		for (Object key : vertex.keySet()) {
			vert.put(key.toString(), vertex.get(key.toString()));
		}
		return connect.addVertex(vert);
	}
			
	public String addEdge(String inVertID, String outVertID, String relation) throws Exception{ //TODO: real exception: "invalid argument"?
		return connect.addEdge(inVertID, outVertID, relation);
	}
	
	public void updateVertex(String VertID, JSONObject vertex) throws Exception{ //TODO: real exception: "invalid argument"?
		Map<String, Object> vert = new HashMap<String, Object>();
		for (Object key : vertex.keySet()) {
			vert.put(key.toString(), vertex.get(key.toString()));
		}
		connect.updateVertex(VertID, vert);
	}
	
	//see Align class
	public List<Object> jsonArrayToList(JSONArray a){
		return connect.jsonArrayToList(a);
	}
	
	//see Align class	
	public Map<String, Object> jsonVertToMap(JSONObject v){
		return connect.jsonVertToMap(v);
	}
}
