package alignment.alignment_v2;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONObject;
import org.json.JSONArray;

public class ConfigFileLoader {
	private String STUCCO_ONTOLOGY = "resources/ontology/stucco_ontology.json";
	private String GRAPH_CONFIG = "resources/ontology/graph_config.json";
	private String OBSERVABLE_TYPES = "resources/ontology/observable_types.json"; 
	
	private JSONObject stuccoOntology = null;
	private JSONObject graphConfig = null;
	private JSONObject observableTypes = null;

	public ConfigFileLoader() {
		try {
			/* required to map new incomming stix xml to json vertex */
			stuccoOntology = new JSONObject(new String(Files.readAllBytes(Paths.get(STUCCO_ONTOLOGY))));
			/* required to determine vertexTypes and edges to construct a graph */
			graphConfig = new JSONObject(new String(Files.readAllBytes(Paths.get(GRAPH_CONFIG))));
			/* required to determine observable type (File, URL, etc.) and provides path to extract name for every type */
			observableTypes = new JSONObject(new String(Files.readAllBytes(Paths.get(OBSERVABLE_TYPES))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public JSONObject getStuccoOntology() {
		return stuccoOntology;
	}
	
	public JSONObject getGraphConfig() {
		return graphConfig;
	}
	
	public JSONObject getVertexOntology(String vertexType) {
		if (stuccoOntology.getJSONObject("definitions").has(vertexType)) {
			return stuccoOntology.getJSONObject("definitions").getJSONObject(vertexType);
		} 
		
		return null;
	}

	public List<String> getRelationsByVertexType(String vertexType) {
		JSONObject vertexConfig = graphConfig.optJSONObject(vertexType);
		if (vertexConfig == null) {
			return null;
		} 
		List<String> relationList = new ArrayList<String>();
		JSONObject edges = vertexConfig.optJSONObject("stixEdges");
		for (Object key : edges.keySet()) {
			relationList.add(key.toString());
		}

		return relationList;
	}

	public JSONObject getObservableType(String type) { 
		return observableTypes.optJSONObject(type);
	}
}
