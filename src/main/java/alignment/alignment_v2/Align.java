package alignment.alignment_v2;

import java.io.IOException;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList; 
import java.util.regex.Matcher;
import java.util.regex.Pattern; 
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Collection; 

import org.json.JSONObject;  
import org.json.JSONArray; 

import java.lang.Math;

import org.jdom2.Document; 
import org.jdom2.Element;
import org.jdom2.Namespace; 
import org.jdom2.Attribute;
import org.jdom2.output.XMLOutputter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.pnnl.stucco.dbconnect.Condition;
import gov.pnnl.stucco.dbconnect.DBConstraint;

/**
 * Aligning JSON graph with existing graph.
 *
 * @author Maria Vincent
 */

public class Align {
	private static final int VERTEX_RETRIES = 2;
	private static final int EDGE_RETRIES = 2;
	private boolean SEARCH_FOR_DUPLICATES = false;
	private boolean ALIGN_VERT_PROPS = false;
	private DBConnectionJson connection = null;
	private Compare compare = null;
	private JSONObject vertsToLoad = null;
	private JSONArray edgesToLoad = null;
	private Map<String, String> stixIDMap = null;
	private Map<String, String> dbIDMap = null;

	private Logger logger = null;

	public Align() {
		logger = LoggerFactory.getLogger(Align.class);
		connection = new DBConnectionJson();
		compare = new Compare();
	}

	public void setSearchForDuplicates(boolean search) {
		SEARCH_FOR_DUPLICATES = search;
	}

	public void setAlignVertProps(boolean align) {
		ALIGN_VERT_PROPS = align;
	}
	
	/* 
	 *	for test purpose only 
	 */
	public DBConnectionJson getConnection() {
		return connection;
	}

	public boolean load(JSONObject newGraphSection) {
		if (newGraphSection == null) {
			return false;
		}

		try {
			stixIDMap = new HashMap<String, String>();
			dbIDMap = new HashMap<String, String>();
			vertsToLoad = newGraphSection.optJSONObject("vertices");
			edgesToLoad = newGraphSection.optJSONArray("edges");

			/* loading vertices */
			boolean loadedVertices = false;
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
			} else {
				logger.info("There are no vertices in this graph!");
				loadedVertices = true;
			}

			updateVertices();

			/* loading edges */
			boolean loadedEdges = false;
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
			} else {
				logger.info("There are no edges in this graph!");
				loadedEdges = true;
			}

			return (loadedVertices && loadedEdges) ? true : false;
		} catch (Exception e) {
			e.printStackTrace();
		}	 
		return false;
	}

	/* 
	 *	searching for duplicates by name, by alias, and by vertices comparison (if SEARCH_FOR_DUPLICATES == true);
	 *	if duplicate found, aligning properties (if ALIGN_VERT_PROPS == true),
	 *	if duplicate was not found, just loading new vertex 
	 */
	private JSONObject loadVertices(JSONObject vertices) {
		Pattern pattern = Pattern.compile("id=\"(\\S+)\"");
		Iterator<String> keys = vertices.keys();
		while (keys.hasNext()) { 
			boolean newVert = true;
			String id = keys.next();
			JSONObject newVertex = vertices.getJSONObject(id);
			try {
				List<DBConstraint> constraints = new ArrayList<DBConstraint>();
				String observableType = newVertex.optString("observableType");
				if (!observableType.isEmpty()) {
					constraints.add(connection.getConstraint("observableType", Condition.eq, observableType));
				}
				String vertexType = newVertex.getString("vertexType");
				constraints.add(connection.getConstraint("vertexType", Condition.eq, vertexType));
				DBConstraint nameConstraint = null;

				/* searching by name first */
				String duplicateVertexId = searchByName(newVertex, constraints);
				newVert = (duplicateVertexId == null);
				if (!newVert) {
		//			logger.info("Found duplicate by name!");
				} 

				/* searching by alias */
				if (newVert) {
					boolean hasAlias = ConfigFileLoader.getVertexOntology(vertexType).getJSONObject("properties").has("alias");
					/* means that vertex type is not an observable, or if it is, then it is observable_composition and not just plain File, etc */
					boolean isNotObservableObject = (!vertexType.equals("Observable") || observableType.equals("Observable_Composition"));
					if (newVert && hasAlias && isNotObservableObject) {
						duplicateVertexId = searchByAlias(newVertex, constraints);
						newVert = (duplicateVertexId == null);
						if (!newVert) {
				//			logger.info("Found duplicate by alias!");
				//			JSONObject duplicateVertex = connection.getVertByID(duplicateVertexId);
				//			logger.info(duplicateVertex.toString(2));
				//			logger.info(newVertex.toString(2));
						} 
					}
				}				

				/* searching by types */
				if (newVert && SEARCH_FOR_DUPLICATES) {
					constraints.remove(nameConstraint);
					duplicateVertexId = findDuplicateVertex(newVertex, constraints);
					newVert = (duplicateVertexId == null);
					if (!newVert) {
			//			logger.info("Found duplicate by types!");
					} 
				} 

				if (!newVert) {
					JSONObject duplicateVertex = connection.getVertByID(duplicateVertexId);
					if (ALIGN_VERT_PROPS) {
						alignVertProps(newVertex, duplicateVertex);
						connection.updateVertex(duplicateVertexId, duplicateVertex);
					}
					String sourceDocumentId = getSourceDocumentId(duplicateVertex, pattern);
					stixIDMap.put(id, sourceDocumentId);
					dbIDMap.put(id, duplicateVertexId);
					keys.remove();
				} else {
					/* if none of the searches found a duplicate, adding new vertex */
					String newVertId = connection.addVertex(newVertex);
					if (newVertId != null) {
						dbIDMap.put(id, newVertId);
						keys.remove();
						List<JSONObject> newEdges = findNewEdges(newVertex, id);
						if (!newEdges.isEmpty()) {
							if (edgesToLoad == null) {
								edgesToLoad = new JSONArray();
							}
							for (JSONObject newEdge : newEdges) {	
								edgesToLoad.put(newEdge);
							}
						}
					} 
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return vertices;
	}

	/* 
	 *	most vertex types have unique names, so db search for duplicate is pretty fast based on just one field
	 */
	private String searchByName(JSONObject newVertex, List<DBConstraint> constraints) {
		DBConstraint nameConstraint = null;
		String newVertName = newVertex.getString("name");
		nameConstraint = connection.getConstraint("name", Condition.eq, newVertName); 
		constraints.add(nameConstraint);
		try {
			List<String> candidateIds = connection.getVertIDsByConstraints(constraints);
		  //	System.out.println("candidate ids: " + candidateIds);
			int condidateCount = candidateIds.size();
			if (condidateCount == 1) {
				constraints.remove(nameConstraint);
				String duplicateVertexId = candidateIds.get(0);
				return duplicateVertexId;
			} else if (condidateCount > 1) {
				logger.info("More that one candidateIds found for:");
				logger.info("				vertexType: " + newVertex.getString("vertexType"));
				logger.info("				name: " + newVertex.getString("name"));
				logger.info("				observableType: " + newVertex.optString("observableType"));
			} 
			constraints.remove(nameConstraint);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	} 

	/*
	 *	some vertices have an alias field;
	 *	in this case, it depends on type of vertex, for example malware would only need one instance from it's name or alias 
	 *	to match another vertex to detect if it is a duplicate;
	 *	in other cases, such Observable_Composition, there is a minimum amount of the same alias entries should be to consider it a dupilcate 
	 */
	private String searchByAlias(JSONObject newVertex, List<DBConstraint> constraints) {
		String vertexType = newVertex.getString("vertexType");
		boolean onlyOneAliasRequired = (vertexType.equals("Malware") || vertexType.equals("Campaign") || vertexType.equals("Threat_Actor"));
		if (onlyOneAliasRequired) {
			return searchForDuplicateByOneRequiredAlias(newVertex, constraints);
		} else if (newVertex.has("alias")) {
			return searchForDuplicateByAliasWithThreshold(newVertex, constraints);
		} else {
			return null;
		}
	}

	private String searchForDuplicateByOneRequiredAlias(JSONObject newVertex, List<DBConstraint> constraints) {
		DBConstraint constraint = connection.getConstraint("name", Condition.eq, newVertex.getString("name"));
		constraints.add(constraint);
		try {
			List<String> candidateIds = connection.getVertIDsByConstraints(constraints);
			if (!candidateIds.isEmpty()) {
				if (candidateIds.size() == 1) {
					return candidateIds.get(0);
				} else if (candidateIds.size() > 1) {
					logger.info("More than one vertex was found for name: " + newVertex.getString("name"));
				}
			} else {
				constraints.remove(constraint);
				constraint = connection.getConstraint("alias", Condition.contains, newVertex.getString("name"));
				constraints.add(constraint);
				candidateIds = connection.getVertIDsByConstraints(constraints);
				if (candidateIds.size() == 1) {
					return candidateIds.get(0);
				} else  if (candidateIds.size() > 1) {
					logger.info("More than one vertex was found for name: " + newVertex.getString("name"));
				} else if (newVertex.has("alias")) {
					Set<Object> alias = (HashSet<Object>) newVertex.get("alias");
					Iterator<Object> iter = alias.iterator();
					while (iter.hasNext()) {
						Object aliasEntry = iter.next();
						constraints.remove(constraint);
						constraint = connection.getConstraint("name", Condition.eq, aliasEntry);
						constraints.add(constraint);
						candidateIds = connection.getVertIDsByConstraints(constraints);
						if (candidateIds.size() == 1) {
							return candidateIds.get(0);
						} else if (candidateIds.size() > 1) {
							logger.info("More than one vertex was found for name: " + newVertex.getString("name"));
						} else {
							constraints.remove(constraint);
							constraint = connection.getConstraint("alias", Condition.contains, aliasEntry);
							constraints.add(constraint);
							candidateIds = connection.getVertIDsByConstraints(constraints);
							if (!candidateIds.isEmpty()) {
								if (candidateIds.size() == 1) {
									return candidateIds.get(0);
								} else if (candidateIds.size() > 1) {
									logger.info("More than one vertex was found for name: " + newVertex.getString("name"));
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			constraints.remove(constraint);
		}

		return null;
	}

	private String searchForDuplicateByAliasWithThreshold(JSONObject newVertex, List<DBConstraint> constraints) {
		double threshold = 0.75;
		DBConstraint constraint = null;
		constraints.add(constraint);
		try {
			Set<Object> alias = (HashSet<Object>)newVertex.get("alias");
			int aliasCount = alias.size();
			Set<String> checkedIds = new HashSet<String>();
			for (Object aliasEntry : alias) {
				constraints.remove(constraint);
				constraint = connection.getConstraint("alias", Condition.contains, aliasEntry);
				constraints.add(constraint);
				List<String> candidateIds = connection.getVertIDsByConstraints(constraints);
				for (String candidateId : candidateIds) {
					if (checkedIds.contains(candidateId)) {
						continue;
					}
					JSONObject candidateDuplicate = connection.getVertByID(candidateId);
					Set<Object> candidateDuplicateAlias = (HashSet<Object>)candidateDuplicate.get("alias");
					int minOverlap = (int) Math.floor(Math.min(aliasCount, candidateDuplicateAlias.size()) * threshold);
					int overlap = 0;
					for (Object candidateName : candidateDuplicateAlias) {
						if (alias.contains(candidateName)) {
							if (++overlap == minOverlap) {
								return candidateId;
							}
						}
					}
				}
				checkedIds.addAll(candidateIds);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			constraints.remove(constraint);
		}

		return null;
	}

	/*
	 *	function returns id from source document, which is original stix xml;
	 *	it is required in cases when duplicate was found,
	 *	to update all the idref's from pointing to it another source documents 
	 */
	private String getSourceDocumentId(JSONObject duplicateVertex, Pattern pattern) {
		String sourceDocument = duplicateVertex.getString("sourceDocument");
		Matcher matcher = pattern.matcher(sourceDocument);
		if (matcher.find()) {
			String stixId = matcher.group(1);
			return stixId;
		} else {
			logger.info("Could not find id in sourceDocument!!!");
		}

		return null;
	}

	/* 	
	 *	updating out verts if there is a duplicate was found for their in verts, 
	 *	so their xml string with idref in it would still point to a correct element when building report
	 */ 
	private void updateVertices() {
		if (edgesToLoad != null) {
			for (int i = 0; i < edgesToLoad.length(); i++) {
				JSONObject edge = edgesToLoad.getJSONObject(i);
				String inVertID = edge.getString("inVertID");
				if (stixIDMap.containsKey(inVertID)) {
					String newId = stixIDMap.get(inVertID);
					String outVertID = edge.getString("outVertID");
					JSONObject vertex = connection.getVertByID(dbIDMap.get(outVertID));
					if (vertex != null) {
						String sourceDocument = vertex.optString("sourceDocument");
						sourceDocument = sourceDocument.replaceFirst(inVertID, newId);
						vertex.put("sourceDocument", sourceDocument);
						try {
							connection.updateVertex(dbIDMap.get(outVertID), vertex);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
			}
		}
	}

	private JSONArray loadEdges(JSONArray edges) {
		JSONArray edgesToRetry = new JSONArray();
		for (int i = 0; i < edges.length(); i++) {
			JSONObject edge = edges.getJSONObject(i);
			try {
				String outVertID = edge.getString("outVertID");
				if (dbIDMap.containsKey(outVertID)) {
					outVertID = dbIDMap.get(outVertID);
				}
				String inVertID = edge.getString("inVertID");
				if (dbIDMap.containsKey(inVertID)) {
					inVertID = dbIDMap.get(inVertID);
				}

				if (outVertID.equals(inVertID)) {
					continue;
				}
				String relation = edge.getString("relation");
				int matchingEdgeCount = connection.getEdgeCountByRelation(inVertID, outVertID, relation);
				//List<String> edgeIDsByVert = connection.getEdgeIDsByVert(inVertID, outVertID, relation);
				// TODO class InMemoryDBConnection returns List of ids for the same outVertID, inVertID, and relation ....
				// not sure why ... needs to be double checked. 
				// if list does not contain a particular relation between two vertices, then we add it ...
				if (matchingEdgeCount > 1) {
					logger.debug("Multiple edges found with the same outVertID, inVertID, and relation!!!");
					continue;
				}
				//if (edgeIDsByVert.isEmpty()) {
				//	String edgeId = connection.addEdge(inVertID, outVertID, relation);
				//	if (edgeId == null) {
				//		edgesToRetry.put(edge);
				//	}
				//}
				//TODO: no longer updates retry list, like above used to.  revisit.
				if (matchingEdgeCount == 0) {
					connection.addEdge(inVertID, outVertID, relation);
				}
			} catch (Exception e) {
				e.printStackTrace();
				edgesToRetry.put(edge);
			}
		}
	
		return edgesToRetry;
	}


	/* 
	 *	function to find duplicate vertex based on the same vertex type and fields comparison
	 */
	private String findDuplicateVertex(JSONObject vertex, List<DBConstraint> constraints) throws Exception {
		double threshold = 0.75;
		List<String> candidateIds = connection.getVertIDsByConstraints(constraints);
		double bestScore = 0.0;
		String bestId = null;
		for (String candidateId : candidateIds) {
			JSONObject candidateVertex = connection.getVertByID(candidateId);
			double score = compare.compareVertices(vertex, candidateVertex, null);
			if (score >= threshold) {
				if (bestId == null || (bestId != null && score > bestScore)) {
					bestId = candidateId;
					bestScore = score;
				} 
			}
		} 

		return bestId;
	}

	/* 
	 * function to set an edges between new IPs and existing AddressRanges or vise versa
	 */
	private List<JSONObject> findNewEdges(JSONObject vert, String id) throws Exception, IOException {
		List<JSONObject> edges = new ArrayList();
		String vertexType = vert.getString("vertexType");
		if (vertexType.equals("AddressRange")) {
			Long endIpInt = vert.optLong("endIPInt");
			Long startIpInt = vert.optLong("startIPInt");
			if (endIpInt != null && startIpInt != null) {
				List<DBConstraint> constraints = new ArrayList<DBConstraint>();
				DBConstraint c = connection.getConstraint("vertexType", Condition.eq, "IP");
				constraints.add(c);
				c = connection.getConstraint("ipInt", Condition.lte, endIpInt);
				constraints.add(c);
				c = connection.getConstraint("ipInt", Condition.gte, startIpInt);
				constraints.add(c);
				List<String> matchIDs = connection.getVertIDsByConstraints(constraints);
				if (matchIDs != null) {
					for (String matchID : matchIDs) {
						JSONObject match = connection.getVertByID(matchID);
						JSONObject edge = new JSONObject();
						edge.put("relation", "Contained_Within");
						edge.put("outVertID", matchID);
						edge.put("inVertID", id);
						edges.add(edge);
					}
				}
			} else {
				logger.warn("address range vert did not have int addresses: " + vert.toString());
			}
		} else if (vertexType.equals("IP")) {
			List<DBConstraint> constraints = new ArrayList<DBConstraint>();
			DBConstraint c = connection.getConstraint("vertexType", Condition.eq, "AddressRange"); 
			constraints.add(c);
			c = connection.getConstraint("endIPInt", Condition.gte, vert.getLong("ipInt"));
			constraints.add(c);
			c = connection.getConstraint("startIPInt", Condition.lte, vert.getLong("ipInt"));
			constraints.add(c);
			List<String> matchIDs = connection.getVertIDsByConstraints(constraints);
			if (matchIDs != null) {
				for (String matchID : matchIDs) {
					JSONObject match = connection.getVertByID(matchID);
					JSONObject edge = new JSONObject();
					edge.put("relation", "Contained_Within");
					edge.put("outVertID", id);
					edge.put("inVertID", matchID);
					edges.add(edge);
				}
			}
		}
		return edges;
	}
		
	/*	function is adding new properties to existing duplicate vertex; 
	 *	only new properties can be added, so properties with the same names and different content
	 *	cannot be combined for now, unless one of elements contains list of children with this tag, 
	 *	then we know that list is allowed and we can append new element. 
	 *	Combination requires more research, and implementation of something like xsld
	 *	with set of rules for combination based on schema, otherwise output may be invalid 
	 */			
	private void alignVertProps(JSONObject newVertex, JSONObject existingVertex) {
		JSONObject vertProperties = ConfigFileLoader.getVertexOntology(newVertex.getString("vertexType")).getJSONObject("properties");
		for (Object keyObject : vertProperties.keySet()) {
			String key = keyObject.toString();
			if (!newVertex.has(key)) {
				continue;
			}
			// TODO: removed sourceDocument alignment since all stix elements must be in particular order
			// to add new element, it's index must be known; 
			// it would require massive config file or use of stix java library; both options are computationally expensive
			if (key.equals("sourceDocument")) {
				// TODO: come up with an ideo of how to combine xml ... since in stix all elements must be in particular order
				//	maybe when stix will move to JSON it will be easier
				continue;
			} else {
				String cardinality = vertProperties.getJSONObject(key).getString("cardinality");
				if (cardinality.equals("set")) {
					Set<Object> set = (HashSet<Object>) newVertex.get(key);
					if (key.equals("alias")) {
						set.add(newVertex.getString("name"));
						set.remove(existingVertex.getString("name"));
					}
					if (existingVertex.has(key)) {
						set.addAll((HashSet<Object>) existingVertex.get(key));
					} 
					/* MUST be casted to Object in order to keep it as a set, otherwise it will convert it to JSONArray */
					existingVertex.put(key, (Object)set);
				}
			}
		}
	}

	public void print(JSONObject v) {
		for (Object key : v.keySet()) {
			if (v.get(key.toString()) instanceof JSONArray) System.out.println(key + " -> JSONArray"); 
			if (v.get(key.toString()) instanceof Collection) System.out.println(key + " -> Collection"); 
		}
	}
}



