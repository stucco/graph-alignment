package alignment.alignment_v2;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

public class ConfigFileLoader {
	private String STIX_ONTOLOGY = "resources/ontology/stix_ontology.json";
	private String VERTEX_TYPE_CONFIG = "resources/ontology/vertex_type_config.json";
	
	private JSONObject ontology = null;
	private JSONObject vertexTypeConfig = null;

	public ConfigFileLoader() {
		try {
			/* required to map new incomming stix xml to vertesType (like is it IP, Port, etc ?) */
			vertexTypeConfig = new JSONObject(new String(Files.readAllBytes(Paths.get(VERTEX_TYPE_CONFIG))));
			/* required to construct a graph, to do all the comparisons, and stix xml editing */
			ontology = new JSONObject(new String(Files.readAllBytes(Paths.get(STIX_ONTOLOGY))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public JSONObject getStuccoOntology() {
		return ontology;
	}
	
	public JSONObject getVertexTypeConfig() {
		return vertexTypeConfig;
	}

	public JSONObject getVertexOntology(String vertexType) {
		if (ontology.getJSONObject("definitions").has(vertexType)) {
			return ontology.getJSONObject("definitions").getJSONObject(vertexType);
		} 
		
		return null;
	}
}
