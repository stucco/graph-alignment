package gov.ornl.stucco.alignment;

import gov.pnnl.stucco.dbconnect.Condition;
import gov.pnnl.stucco.dbconnect.DBConstraint;
import gov.pnnl.stucco.dbconnect.DBConnectionAlignment;
import gov.pnnl.stucco.dbconnect.DBConnectionFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * NOTE: two environment variable must be defined:
 *       STUCCO_DB_CONFIG=<path/filename.yml>
 *       STUCCO_DB_TYPE= INMEMORY|ORIENTDB|TITAN|NEO4J
 */
public class DBConnectionJson {

	private DBConnectionFactory factory;
    private DBConnectionAlignment connect = null;

	public DBConnectionJson(){
		String type = System.getenv("STUCCO_DB_TYPE");
        if (type == null) {
            throw (new NullPointerException("Missing environment variable STUCCO_DB_TYPE"));
        }

        factory = DBConnectionFactory.getFactory(DBConnectionFactory.Type.valueOf(type));

        String config = System.getenv("STUCCO_DB_CONFIG");
        if (config == null) {
            throw (new NullPointerException("Missing environment variable STUCCO_DB_CONFIG"));
        }
        factory.setConfiguration(config);

        connect = factory.getDBConnectionAlignment();
        connect.open();
	}

	public long getVertCount() {
		return connect.getVertCount();
	}

	public long getEdgeCount() {
		return connect.getEdgeCount();
	}

	public JSONObject getVertByID(String vertID){
		Map<String, Object> vert = connect.getVertByID(vertID);
		JSONObject jsonVert = new JSONObject();
		for (Map.Entry<String, Object> entry : vert.entrySet()) {
			jsonVert.put(entry.getKey(), entry.getValue());
		}
		return jsonVert;
	}

	public JSONObject getVertByName(String vertName){
		Map<String, Object> vert = getVertByNameL(vertName);
		if (vert == null) {
			return null;
		}
		JSONObject jsonVert = new JSONObject();
		for (Map.Entry<String, Object> entry : vert.entrySet()) {
			jsonVert.put(entry.getKey(), entry.getValue());
		}
		return jsonVert;
	}

	public String getVertIDByName(String vertName){
		return getVertIDByNameL(vertName);
	}
	
	public JSONArray getInEdges(String outVertID){
		List<Map<String, Object>> inEdges = connect.getInEdges(outVertID);
		JSONArray array = new JSONArray();
		for (Map<String, Object> inEdge : inEdges) {
			JSONObject edge = new JSONObject(inEdge);
			array.put(edge);
		}

		return array;
	}

	public JSONArray getOutEdges(String inVertID){
		List<Map<String, Object>> outEdges = connect.getInEdges(inVertID);
		JSONArray array = new JSONArray();
		for (Map<String, Object> outEdge : outEdges) {
			JSONObject edge = new JSONObject(outEdge);
			array.put(edge);
		}

		return array;
	}

	public List<String> getInVertIDsByRelation(String outVertID, String relation){
		return connect.getInVertIDsByRelation(outVertID, relation);
	}
	
	public List<String> getOutVertIDsByRelation(String inVertID, String relation){
		return connect.getOutVertIDsByRelation(inVertID, relation);
	}
	
	public List<String> getVertIDsByRelation(String vertID, String relation){
		return connect.getVertIDsByRelation(vertID, relation);
	}
	
	public int getEdgeCountByRelation(String inVertID, String outVertID, String relation){
		return connect.getEdgeCountByRelation(inVertID, outVertID, relation);
	}
	
	public List<String> getVertIDsByConstraints(List<DBConstraint> constraints){
		return connect.getVertIDsByConstraints(constraints);
	}
	
	public void removeVertByID(String vertID){
		connect.removeVertByID(vertID);
	}
	
	public String addVertex(JSONObject vertex){
		Map<String, Object> vert = new HashMap<String, Object>();
		for (Object key : vertex.keySet()) {
			vert.put(key.toString(), vertex.get(key.toString()));
		}
		return connect.addVertex(vert);
	}
			
	public void addEdge(String inVertID, String outVertID, String relation){
		connect.addEdge(inVertID, outVertID, relation);
	}
	
	public void updateVertex(String VertID, JSONObject vertex){
		Map<String, Object> vert = new HashMap<String, Object>();
		for (Object key : vertex.keySet()) {
			vert.put(key.toString(), vertex.get(key.toString()));
		}
		connect.updateVertex(VertID, vert);
	}
	
	/**
     * get the vertex's property map using the vertex's canonical name
     * @param vertName
     * @return property map
     */
    private List<Map<String,Object>> getVertsByNameL(String vertName) {
        List<Map<String,Object>> retVal = new LinkedList<Map<String,Object>>();
        List<String> ids = getVertIDsByNameL(vertName);
        if(ids == null)
            return null;
        for(String currID : ids){
            Map<String, Object> currVert = connect.getVertByID(currID);
            if(currVert == null)
                throw new IllegalStateException("bad state: found vert id with no content.");
            retVal.add(currVert);
        }
        return retVal;
    }
    
    private Map<String,Object> getVertByNameL(String vertName){
    	List<Map<String,Object>> result = getVertsByNameL(vertName);
    	if(result == null || result.size() == 0){
    		return null;
    	}
    	return result.get(0);
    }

    /**
     * get the vertexID using the canonical name
     * @param vertName
     * @return ID
     */
    private List<String> getVertIDsByNameL(String vertName){
    	if (vertName == null) {
            return null;
      } else if (vertName.equals("")) {
      	return null;
      }
    	List<DBConstraint> constraints = new ArrayList<DBConstraint>(1);
    	DBConstraint c1 = connect.getConstraint("name", Condition.eq, vertName );
    	constraints.add( c1 );
    	return connect.getVertIDsByConstraints(constraints);
    }
    
    private String getVertIDByNameL(String vertName){
    	List<String> result = getVertIDsByNameL(vertName);
    	if(result == null || result.size() == 0){
    		return null;
    	}
    	return result.get(0);
    }
    
	//see Align class
	public static List<Object> jsonArrayToList(JSONArray a){
		List<Object> l = new ArrayList<Object>();
		for(int i=0; i<a.length(); i++){
			l.add(a.get(i));
		}
		return l;
	}

	//see Align class	
	public static Map<String, Object> jsonVertToMap(JSONObject v){
		Map<String, Object> vert = new HashMap<String, Object>();
		for(Object k : v.keySet()){
			String key = (String) k;
			Object value = v.get(key);
			if(value instanceof JSONArray){
				value = jsonArrayToList((JSONArray)value);
			}
			else if(value instanceof JSONObject){
				System.out.println("WARN: jsonVertToMap: unexpected property type: JSONObject for property " + key + "\n" + v);
			}
			vert.put(key, value);
		}
		return vert;
	}
	
	public DBConstraint getConstraint(String prop, Condition cond, Object val ){
		return connect.getConstraint(prop, cond, val );
	}
}
