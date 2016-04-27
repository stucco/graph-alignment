package alignment.alignment_v2;

import java.io.IOException;

import org.apache.commons.io.IOUtils;

import org.json.JSONObject;

public abstract class ConfigFileLoader {

	private static final String _stucco_ontology = "ontology/stucco_ontology.json";
	private static final String _cybox_objects = "ontology/cybox_ontology.json";

	public static JSONObject stuccoOntology;
	public static JSONObject cyboxObjects; 

	static {
		try {
				/* required to map new incomming stix xml to json vertex */
				stuccoOntology = new JSONObject(IOUtils.toString(ConfigFileLoader.class.getClassLoader().getResourceAsStream(_stucco_ontology), "UTF-8"));
				/* required to determine observable type (File, URL, etc.) and provides path to extract name for every type */
				cyboxObjects = new JSONObject(IOUtils.toString(ConfigFileLoader.class.getClassLoader().getResourceAsStream(_cybox_objects), "UTF-8"));
		} catch (IOException e) {
			e.printStackTrace();
		} 
	}
	
	public static JSONObject getVertexOntology(String vertexType) {
		if (stuccoOntology.getJSONObject("definitions").has(vertexType)) {
			return stuccoOntology.getJSONObject("definitions").getJSONObject(vertexType);
		} 
		
		return null;
	}

	public static JSONObject getObservableType(String type) { 
		return cyboxObjects.optJSONObject(type);
	}
}
