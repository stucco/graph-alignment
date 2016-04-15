package alignment.alignment_v2;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

abstract class ConfigFileLoader {

	private static final String _stucco_ontology = "resources/ontology/stucco_ontology.json";
	private static final String _cybox_objects = "resources/ontology/cybox_ontology.json";
	
	static JSONObject stuccoOntology;
	static JSONObject cyboxObjects; 

	static {
		try {
			/* required to map new incomming stix xml to json vertex */
			stuccoOntology = new JSONObject(new String(Files.readAllBytes(Paths.get(_stucco_ontology))));
			/* required to determine observable type (File, URL, etc.) and provides path to extract name for every type */
			cyboxObjects = new JSONObject(new String(Files.readAllBytes(Paths.get(_cybox_objects))));
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
	public static JSONObject loadConfig(String fileName) {
		try {
			return new JSONObject(new String(Files.readAllBytes(Paths.get(fileName))));
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
