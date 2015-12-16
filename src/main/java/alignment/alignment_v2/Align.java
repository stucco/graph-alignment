package alignment.alignment_v2;

import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Align {
	
	private static final boolean SEARCH_FOR_DUPLICATES = true;
	private static final boolean ALIGN_VERT_PROPS = false;
	private static final int VERTEX_RETRIES = 2;
	private static final int EDGE_RETRIES = 2;
	private Logger logger = null;
	private ConfigFileLoader config = null;
	private InMemoryDBConnectionJson connection = null;
	private Compare compare = null;

	public Align() {
		logger = LoggerFactory.getLogger(Align.class);
		connection = new InMemoryDBConnectionJson();
		config = new ConfigFileLoader();
		compare = new Compare();
	}
	
	public boolean load(JSONObject newGraphSection) throws Exception {
		boolean loadedVertices = false;
		/* loading vertices */
		if (newGraphSection.has("vertices")) {
			JSONObject vertsToLoad = newGraphSection.getJSONObject("vertices");
			for (int currTry = 0; currTry < VERTEX_RETRIES; currTry++) {
				vertsToLoad = loadVertices(vertsToLoad);
				if (vertsToLoad.length() == 0) {
					loadedVertices = true;
					break;
				}
			}
		} 
		boolean loadedEdges = false;
		/* loading edges */
		if (newGraphSection.has("edges")) {
			JSONArray edgesToLoad = newGraphSection.getJSONArray("edges");
			for (int currTry = 0; currTry < EDGE_RETRIES; currTry++) {
				edgesToLoad = loadEdges(edgesToLoad);
				if (edgesToLoad.length() == 0) {
					loadedEdges = true;
					break;
				}
			}
		}
		return (loadedVertices && loadedEdges) ? true : false;
	}
			
	private JSONObject loadVertices(JSONObject vertices) throws Exception {
		JSONObject vertsToRetry = new JSONObject();
		for (Object id : vertices.keySet()) {
			JSONObject newVertex = vertices.getJSONObject(id.toString());
			String newVertName = newVertex.getString("name"); //should always be valid since it is undergoing required properties check while converting to json
			String vertId = connection.getVertIDByName(newVertName);

			boolean newVert = (vertId == null);
			if (newVert && SEARCH_FOR_DUPLICATES) {
				String duplicateId = findDuplicateVertex(newVertex);
				newVert = (duplicateId == null);
			}
			if (newVert) { 
				String newVertId = connection.addVertex(newVertex);
				if (newVertId == null) {
					vertsToRetry.put(id.toString(), newVertex);
				}
			} else {
				if (ALIGN_VERT_PROPS) {
					// do the aligning of new vert properties
				} else {
					logger.debug("Vertex exists");
					logger.debug("Attempted to add vertex when duplicate exists.  ALIGN_VERT_PROPS is false, so ignoring new vert.  vert was: " + newVertex);
				}
			}
		}
		return vertsToRetry;
	}

	private JSONArray loadEdges(JSONArray edges) {
		return new JSONArray();
	}

	private String findDuplicateVertex(JSONObject vertex) {
		String vertexType = vertex.getString("vertexType");
		JSONObject vertexOntology = config.getVertexOntology(vertexType);
		List<String> candidateIds = connection.getVertIDsByProperty("vertexType", vertexType);

		double threshold = 0.75;
		String bestId = null;
		double bestScore = 0.0;
		for (String candidateId : candidateIds) {
			JSONObject candidateVertex = connection.getVertByID(candidateId);
			double score = compare.compareVertices(vertex, candidateVertex, vertexOntology);
			if (score >= threshold) {
				if (bestId == null || (bestId != null && score > bestScore)) {
					bestId = candidateId;
					bestScore = score;
				} 
			}
		}

		return bestId;
	}
}
