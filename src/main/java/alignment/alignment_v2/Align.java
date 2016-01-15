package alignment.alignment_v2;

import java.io.IOException;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONObject;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.output.XMLOutputter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Align {
	
	private static final int VERTEX_RETRIES = 2;
	private static final int EDGE_RETRIES = 2;
	
	//SEARCH_FOR_DUPLICATE in most cases should always be true, since many STIX components do not have a unique name,
 	// so to combine we should alway look for duplicates by comparing properties, except cases when graph contains only stucco unique vertices (IP, Port, etc.);
	private static boolean SEARCH_FOR_DUPLICATES = true;
	private static boolean ALIGN_VERT_PROPS = true;
	private Logger logger = null;
	private ConfigFileLoader config = null;
	private InMemoryDBConnectionJson connection = null;
	private Compare compare = null;
	private JSONObject newGraphSection = null;
	private JSONObject vertsToLoad = null;
	private JSONArray edgesToLoad = null;
	private Map<String, JSONObject> existingIndicatorsMap = null;

	public Align() {
		logger = LoggerFactory.getLogger(Align.class);
		connection = new InMemoryDBConnectionJson();
		config = new ConfigFileLoader();
		compare = new Compare();
	}

	public void setSearchForDuplicates(boolean search) {
		SEARCH_FOR_DUPLICATES = search;
	}

	public void setAlignVertProps(boolean align) {
		ALIGN_VERT_PROPS = align;
	}
	
	/* for test purpose */
	public InMemoryDBConnectionJson getConnection() {
		return connection;
	}

	public boolean load(JSONObject newGraphSection) throws Exception {
		this.newGraphSection = newGraphSection;
		vertsToLoad = newGraphSection.optJSONObject("vertices");
		edgesToLoad = newGraphSection.optJSONArray("edges");
		if (vertsToLoad == null) {
			vertsToLoad = new JSONObject();
		}
		if (edgesToLoad == null) {
			edgesToLoad = new JSONArray();
		}

		// removing Indicators, since in most cases they serve as a connector between 
		// different types of STIX components, and needs to be aligned bases on a subgraph comparison
		// and not just by itself
		JSONObject indicators = new JSONObject();
		Set<String> ids = vertsToLoad.keySet();
		List<String> indicatorIds = new ArrayList();
		for (String key : vertsToLoad.keySet()) {
			String id = key.toString();
			JSONObject vertex = vertsToLoad.getJSONObject(id);
			if (vertex.getString("vertexType").equals("Indicator")) {
				indicators.put(id, vertex);
				indicatorIds.add(id);
			}
		}
		for (String id : indicatorIds) {
			vertsToLoad.remove(id);
		}

		boolean loadedVertices = false;
		/* loading vertices */
		if (vertsToLoad != null) {
			for (int currTry = 0; currTry < VERTEX_RETRIES; currTry++) {
				vertsToLoad = loadVertices(vertsToLoad);
				if (vertsToLoad.length() == 0) {
					loadedVertices = true;
					break;
				} else if (currTry == VERTEX_RETRIES) {
					logger.error("Could not add vertex!  Vertex is out of retry attempts!");
				}
			}
		}

		boolean loadedIndicatorVertices = false;
		/* loading indicators */
		vertsToLoad = indicators;
		if (vertsToLoad != null) {
			for (int currTry = 0; currTry < VERTEX_RETRIES; currTry++) {
				vertsToLoad = loadVertices(vertsToLoad);
				if (vertsToLoad.length() == 0) {
					loadedVertices = true;
					break;
				} else if (currTry == VERTEX_RETRIES) {
					logger.error("Could not add Indicator Vertex!  Vertex is out of retry attempts!");
				}
			}
		}
		
		boolean loadedEdges = false;
		/* loading edges */
		if (edgesToLoad != null) {
			for (int currTry = 0; currTry < EDGE_RETRIES; currTry++) {
				edgesToLoad = loadEdges(edgesToLoad);
				if (edgesToLoad.length() == 0) {
					loadedEdges = true;
					break;
				} else if (currTry == EDGE_RETRIES) {
					logger.error("Could not add edge! Edge is out of retry attempts!");
				}
			}
		}
		return (loadedVertices && loadedEdges) ? true : false;
	}

	private JSONObject loadVertices(JSONObject vertices) throws Exception {
		JSONObject vertsToRetry = new JSONObject();
		for (Object id : vertices.keySet()) {
			JSONObject newVertex = vertices.getJSONObject(id.toString());
			//should always be valid since it is undergoing required properties check while converting to json
			String newVertName = newVertex.getString("name"); 
			String vertId = connection.getVertIDByName(newVertName);
			boolean newVert = (vertId == null);
			if (newVert && SEARCH_FOR_DUPLICATES) {
				String vertexType = newVertex.getString("vertexType");
				String duplicateId = findDuplicateVertex(newVertex);
				newVert = (duplicateId == null);
				if (duplicateId != null) {
					JSONObject duplicateVertex = connection.getVertByID(duplicateId);
					updateEdges(newVertex.getString("name"), duplicateVertex.getString("name")); 
					updateVertices(newVertex.getString("name"), duplicateVertex.getString("name")); 
					if (ALIGN_VERT_PROPS) {
						// do the aligning of new vert properties
						JSONObject existingVert = connection.getVertByID(duplicateId);
						alignVertProps(newVertex, duplicateVertex);
						connection.updateVertex(duplicateId, duplicateVertex);
					} else {
						logger.debug("Vertex exists");
						logger.debug("Attempted to add vertex when duplicate exists.  ALIGN_VERT_PROPS is false, so ignoring new vert.  vert was: " + newVertex);
					}
				}
			}
			if (newVert) { 
				String newVertId = connection.addVertex(newVertex);
				if (newVertId == null) {
					vertsToRetry.put(id.toString(), newVertex);
				} else {
					List<JSONObject> newEdges = findNewEdges(newVertex);
					for (JSONObject newEdge : newEdges) {	
						edgesToLoad.put(newEdge);
					}
				}
			} 
		}
		return vertsToRetry;
	}

	private JSONArray loadEdges(JSONArray edges) throws Exception {
		JSONArray edgesToRetry = new JSONArray();
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			String outVertID = edge.getString("outVertID");
			String inVertID = edge.getString("inVertID");
			String relation = edge.getString("relation");
			List<String> edgeIDsByVert = connection.getEdgeIDsByVert(inVertID, outVertID, relation);
			// TODO class InMemoryDBConnection returns List of ids for the same outVertID, inVertID, and relation ....
			// not sure why ... needs to be double checked. 
			// if list does not contain a particular relation between two vertices, then we add it ...
			if (edgeIDsByVert.size() > 1) {
				logger.debug("Multiple edges found with the same outVertID, inVertID, and relation!!!");
			}
			if (edgeIDsByVert.isEmpty()) {
				String edgeId = connection.addEdge(inVertID, outVertID, relation);
				if (edgeId == null) {
					edgesToRetry.put(edge);
				}
			}
		}
	
		return edgesToRetry;
	}

	private String findDuplicateVertex(JSONObject vertex) throws Exception {
		String vertexType = vertex.getString("vertexType");
		if (vertexType.equals("Indicator")) {
			return findIndicatorDuplicate(vertex);
		}
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
			
	/* to find indicator duplicate we have to compare new subgraph containing new indicator with
	   existing subgraphs with indicators, since indicator is a connector between multiple stix components */
	private String findIndicatorDuplicate(JSONObject indicator) throws Exception {
		if (existingIndicatorsMap == null) {
			existingIndicatorsMap = new HashMap();
		}
		loadExistingIndicatorsMap();
		double threshold = 0.75;
		JSONObject newVerts = newGraphSection.optJSONObject("vertices");

		Map<String, List<String>> outVertIDsMap = setOutVertIDsMap(indicator.getString("name"));
		Map<String, List<String>> inVertIDsMap = setInVertIDsMap(indicator.getString("name"));

		String duplicateId = null;
		double bestDuplicateScore = 0.0;
		int count = 0;
		for (String id : existingIndicatorsMap.keySet()) {
			JSONObject existingIndicator = existingIndicatorsMap.get(id);
			double totalScore = 0.0;
			/* searching for duplicates between vertices that are pointing to existing indicator and new indicator */
			if (!inVertIDsMap.isEmpty()) {
				for (String relation : inVertIDsMap.keySet()) {
					List<String> newInVertIDsList = inVertIDsMap.get(relation);	
					List<String> existingInVertIDsList = connection.getInVertIDsByRelation(existingIndicator.getString("name"), relation);
					double relationTotalScore = 0.0;
					for (String newInVertID : newInVertIDsList) {
						JSONObject newInVert = newVerts.getJSONObject(newInVertID);
						double bestScore = 0.0;
						for (String existingInVertID : existingInVertIDsList) {
							JSONObject existingInVert = connection.getVertByName(existingInVertID);
							double score = compare.compareVertices(newInVert, existingInVert, null);
							if (score >= threshold && score > bestScore) {
								bestScore = score;
							}
						}	
						relationTotalScore = relationTotalScore + bestScore;	
					}
					totalScore = totalScore + ((relationTotalScore == 0.0) ? 0.0 : Math.min(newInVertIDsList.size(), existingInVertIDsList.size())/relationTotalScore);
				}
			}
			/* searching for duplicates between vertices that existing indicator is pointing to and new indicator */
			if (outVertIDsMap.isEmpty()) {
				for (String relation : outVertIDsMap.keySet()) {
					List<String> newOutVertIDsList = outVertIDsMap.get(relation);	
					List<String> existingOutVertIDsList = connection.getOutVertIDsByRelation(existingIndicator.getString("name"), relation);
					double relationTotalScore = 0.0;
					for (String newOutVertID : newOutVertIDsList) {
						JSONObject newOutVert = newVerts.getJSONObject(newOutVertID);
						double bestScore = 0.0;
						for (String existingOutVertID : existingOutVertIDsList) {
							JSONObject existingOutVert = connection.getVertByName(existingOutVertID);
							double score = compare.compareVertices(newOutVert, existingOutVert, null);
							if (score >= threshold && score > bestScore) {
								bestScore = score;
							}
						}	
						relationTotalScore = relationTotalScore + bestScore;	
					}
					totalScore = totalScore + ((relationTotalScore == 0.0) ? 0.0 : Math.min(newOutVertIDsList.size(), existingOutVertIDsList.size())/relationTotalScore);
				}

			}
			totalScore = (compare.compareVertices(indicator, existingIndicator, null) * 0.25) + (totalScore * 0.75);
			if (totalScore >= threshold) {
				if (totalScore > bestDuplicateScore) {
					duplicateId = id;
				}
			}
		}
		JSONObject duplicate = connection.getVertByID(duplicateId);

		return duplicateId;
	}

	/* loading all the indicators from existing graph to find duplicate */
	private void loadExistingIndicatorsMap() {
		List<String> existingIndicatorsIdList = connection.getVertIDsByProperty("vertexType", "Indicator");
		for (String id : existingIndicatorsIdList) {
			JSONObject existingIndicator = connection.getVertByID(id);
			if (existingIndicator != null) {
				existingIndicatorsMap.put(id, existingIndicator);
			}
		}
	}

	/* mapping relatin between new indicator to related InVertex id from new graph */
	private Map<String, List<String>> setInVertIDsMap(String id) {
		JSONArray edges = newGraphSection.optJSONArray("edges");
		Map<String, List<String>> inVertIDsMap = new HashMap<String, List<String>>();
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("outVertID").equals(id)) {
				List<String> inVertIDsList = (inVertIDsMap.containsKey(edge.get("relation"))) ? inVertIDsMap.get(edge.get("relation")) : new ArrayList<String>();
				inVertIDsList.add(edge.getString("inVertID"));
				inVertIDsMap.put(edge.getString("relation"), inVertIDsList);
			}
		}
		
		return inVertIDsMap;
	}

	/* mapping new relatin between new indicator to related outVertex id from new graph */
	private Map<String, List<String>> setOutVertIDsMap(String id) {
		JSONArray edges = newGraphSection.optJSONArray("edges");
		Map<String, List<String>> inVertIDsMap = new HashMap<String, List<String>>();
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			if (edge.getString("inVertID").equals(id)) {
				List<String> inVertIDsList = (inVertIDsMap.containsKey(edge.get("relation"))) ? inVertIDsMap.get(edge.get("relation")) : new ArrayList<String>();
				inVertIDsList.add(edge.getString("outVertID"));
				inVertIDsMap.put(edge.getString("relation"), inVertIDsList);
			}
		}
		
		return inVertIDsMap;
	}
	
	/* if duplicate vertex found, updating edgesToLoad to match duplicate name, 
	   since in most cases stix element's names are unique UUID */
	void updateEdges(String oldID, String newID) {
		for (int i = 0; i < edgesToLoad.length(); i++) {
			JSONObject edge = edgesToLoad.getJSONObject(i);
			String inVertID = edge.getString("inVertID");
			String outVertID = edge.getString("outVertID");
			if (inVertID.equals(oldID)) {
				edge.put("inVertID", newID);
			}
			if (outVertID.equals(oldID)) {
				edge.put("outVertID", newID);
			}
		}
	}

	/* if duplicate vertex found, updating vertsToLoad from vertex name duplicate name, 
           since in most cases stix element's names are unique UUID */
	void updateVertices(String oldID, String newID) {
		vertsToLoad = newGraphSection.optJSONObject("vertices");
		for (Object key : vertsToLoad.keySet()) {
			String id = key.toString();
			if (id.equals(oldID)) {
				JSONObject vert = vertsToLoad.getJSONObject(id);
				vert.put("name", newID);
				vertsToLoad.put(newID, vert);
				vertsToLoad.remove(id);
			}
		}
	}

	/* function to set an edges between new IPs and existing AddressRanges */
	private List<JSONObject> findNewEdges(JSONObject vert) throws IOException, Exception{
		List<JSONObject> edges = new ArrayList();
		String vertexType = vert.getString("vertexType");
		if (vertexType.equals("AddressRange")) {
			long endIpInt = vert.optLong("endIPInt");
			long startIpInt = vert.optLong("startIPInt");
			if (endIpInt != 0 && startIpInt != 0) {
				List<Constraint> constraints = new ArrayList<Constraint>();
				Constraint c = new Constraint("vertexType", Constraint.Condition.eq, "IP");
				constraints.add(c);
				c = new Constraint("ipInt", Constraint.Condition.lte, endIpInt);
				constraints.add(c);
				c = new Constraint("ipInt", Constraint.Condition.gte, startIpInt);
				constraints.add(c);
				List<String> matchIDs = connection.getVertIDsByConstraints(constraints);
				if (matchIDs != null) {
					for (String matchID : matchIDs) {
						JSONObject match = connection.getVertByID(matchID);
						JSONObject edge = new JSONObject();
						edge.put("relation", "Contained_Within");
						edge.put("outVertID", match.getString("name"));
						edge.put("inVertID", vert.getString("name"));
						edges.add(edge);
					}
				}
			} else {
				logger.warn("address range vert did not have int addresses: " + vert.toString());
			}
		} else if (vertexType.equals("IP")) {
			List<Constraint> constraints = new ArrayList<Constraint>();
			Constraint c = new Constraint("vertexType", Constraint.Condition.eq, "AddressRange");
			constraints.add(c);
			c = new Constraint("endIPInt", Constraint.Condition.gte, vert.getLong("ipInt"));
			constraints.add(c);
			c = new Constraint("startIPInt", Constraint.Condition.lte, vert.getLong("ipInt"));
			constraints.add(c);
			List<String> matchIDs = connection.getVertIDsByConstraints(constraints);
			if (matchIDs != null) {
				for (String matchID : matchIDs) {
					JSONObject match = connection.getVertByID(matchID);
					JSONObject edge = new JSONObject();
					edge.put("relation", "Contained_Within");
					edge.put("outVertID", vert.getString("name"));
					edge.put("inVertID", match.getString("name"));
					edges.add(edge);
				}
			}
		}
		return edges;
	}
		
	/* function is adding new properties to existing duplicate vertex; 
	   only new properties can be added, so properties with the same names and different content
	   cannot be combined for now, unless one of elements contains list of children with this tag, 
	   then we know that list is allowed and we can append new element. 
	   Combination requires more research, and implementation of something like xsld
	   with set of rules for combination based on schema, otherwise output may be invalid */			
	private void alignVertProps(JSONObject newVertex, JSONObject existingVertex) {
		for (Object keyObject : newVertex.keySet()) {
			String key = keyObject.toString();
			if (key.equals("sourceDocument")) {
				Document newDoc = PreprocessSTIXwithJDOM2.parseXMLText(newVertex.getString("sourceDocument"));
				Document existingDoc = PreprocessSTIXwithJDOM2.parseXMLText(existingVertex.getString("sourceDocument"));
				combineElements(newDoc.getRootElement(), existingDoc.getRootElement());
				existingVertex.put("sourceDocument", new XMLOutputter().outputString(existingDoc));
			} else {
				JSONArray array1 = newVertex.optJSONArray(key);
				if (array1 != null) {
					JSONArray array2 = existingVertex.optJSONArray(key);	
					if (array2 == null) {
						//add array1 to existingVertex
						existingVertex.put(key, array1);
					} else {
						//combine arrays
						List<Integer> indexToAddList = new ArrayList<Integer>();
						for (int i = 0; i < array1.length(); i++) {
							String content1 = array1.getString(i);
							for (int j = 0; j < array2.length(); j++) {
								String  content2 = array2.getString(j);
								if (!content1.equals(content2)) {
									indexToAddList.add(i);	
								}
							}
						}
						for (Integer index : indexToAddList) {
							array2.put(array1.getString(index));
						}
						existingVertex.put(key, array2);
					}
				}
			}
		}
	}

	/* public for test purpose only */
	public void combineElements(Element e1, Element e2) {
		double threshold = 0.75;
		Map<String, Namespace> elementMap1 = Compare.getTagMap(e1);
		Map<String, Namespace> elementMap2 = Compare.getTagMap(e2);

		for (String tag : elementMap1.keySet()) {
			/* case 1: if e1 contains element with this tag and e2 doesn't, 
			   then adding whole element with this tag from e1 to e2 */ 
			if (!elementMap2.containsKey(tag)) {
				List<Element> list1 = e1.getChildren(tag, elementMap1.get(tag));
				for (Element elementToAdd : list1) {
					e2.addContent(elementToAdd.detach());
				}
			} else {
				List<Element> list1 = e1.getChildren(tag, elementMap1.get(tag));
				List<Element> list2 = e2.getChildren(tag, elementMap1.get(tag));

			/* case 2: if both elements have children with this tag */

				/* case 2.1: if both elements have children with the tag in single appearence; */
				if (list1.size() == 1 && list2.size() == 1) {
					String text1 = list1.get(0).getTextNormalize();
					String text2 = list2.get(0).getTextNormalize();
					
					/* case 2.1.1: if both elements contain text, then rules should be written 
						based on stix xsd on how to combine them .... if list is allowed ? 
						if delimiter is allowed ? ... if property shoudl be updated based on timestamp ? */
					if (!text1.isEmpty() || !text2.isEmpty()) {
						double score = compare.defaultComparison(text1, text2);
						if (score < threshold) {
							logger.info(" - text1 most likely is new and needs to be combined somehow ... ");
							logger.info("   do not know if list is allowed .... or should it be updated based on timestamp?");
							logger.info("   or some other rule should be made ...");
						} 
					} else {
					/* case 2.1.2: if elements contain children, then continue recursively compare children */
						combineElements(list1.get(0), list2.get(0));
					}
				} else {
					/* case 2.2: if eather one of elements have a list of children with this tag means that list is allowed here
						and elements should be combined based on list comparison */
					combineLists(list1, list2, e2);
				}
			}
		}
	}

	/* function to combine lists omitting duplicates by using comparison */
	private void combineLists(List<Element> list1, List<Element> list2, Element elementToEdit) {
		double threshold = 0.75;
		PreprocessSTIXwithJDOM2 p = new PreprocessSTIXwithJDOM2();
		List<Element> newElementList = new ArrayList<Element>();
		for (Element e1 : list1) {
			double bestScore = 0.0;
			Element bestElement = null;
			for (Element e2 : list2) {
				double score = compare.compareDocumentElements(e1, e2);
				if (score > bestScore) {
					bestScore = score;
					bestElement = e2;
				}
			}
			/* if duplicate for element from list1 was not found in list2, element should be appended */
			if (bestScore < threshold) {
				newElementList.add(e1);
			}
			if (bestScore >= threshold) {
				combineElements(e1, bestElement);	
			}
		}

		for (Element newElement : newElementList) {
			elementToEdit.addContent(newElement.detach());
		}
	}
}
