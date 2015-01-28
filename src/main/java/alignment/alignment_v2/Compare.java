package alignment.alignment_v2;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import alignment.comparisons.SmithWaterman;
import alignment.comparisons.WHIRL;

public class Compare {

	/*
	private Align align;
	private Logger logger;
	private Comparison comparison;
	private WHIRL whirl;
	 */

	public static double compareVertices(Map<String, Object> vert1, Map<String, Object> vert2, Map<String, Map<String, Object>> configProperties){
		Map<String, Object> props1 = (Map<String, Object>)vert1.get("_properties");
		Map<String, Object> props2 = (Map<String, Object>)vert2.get("_properties");
		List<String> props = new ArrayList<String>(); 
		Object props1keys[] = props1.keySet().toArray();
		for(int i=0; i<props1keys.length; i++){
			if(props2.containsKey((String)props1keys[i])){
				props.add((String)props1keys[i]);
			}
		}
		Double score = 0.0;
		for(int i=0; i<props.size(); i++){
			String p = props.get(i);
			Map<String, Object> propConf = configProperties.get(p);
			if(propConf != null) //eg. "name" property.
				score += compareProperties(p, props1.get(p), props2.get(p), propConf);
		}
		return score;
	}

	public static double compareProperties (String propertyName, Object property1, Object property2, Map<String, Object> configProperties) {

		//Comparison comparison;
		WHIRL whirl;

		Logger logger = LoggerFactory.getLogger(Align.class);
		//comparison = new Comparison();

		Double score = 0.0;
		Double comparisonWeight = 1.0;
		String comparisonFunction = new String("");
		comparisonFunction = configProperties.get("comparisonFunction").toString();
		comparisonWeight = new Double (configProperties.get("comparisonWeight").toString());

		//was going to use a switch statement, but switch with strings is not supported by eclipse
		if (comparisonFunction.equals("exact"))	{
			if (property1.equals(property2))
				score = score + 1 * comparisonWeight;
		}
		//time should be standardized  
		if (comparisonFunction.equals("compareTimestamps"))	{
			//TODO: timestamps need to be standardized before this can happen
			Long timestamp1 = null;
			Long timestamp2 = null;
			try{
				if(property1 instanceof Long)
					timestamp1 = (Long)property1;
				if(property2 instanceof Long)
					timestamp2 = (Long)property2;
				if(property1 instanceof Integer)
					timestamp1 = Long.valueOf((Integer)property1);
				if(property2 instanceof Integer)
					timestamp2 = Long.valueOf((Integer)property2);
				if(property1 instanceof String)
					timestamp1 = Long.valueOf((String)property1);
				if(property2 instanceof String)
					timestamp2 = Long.valueOf((String)property2);
			}catch(ClassCastException e){
				logger.warn("Could not convert timestamps: bad format?  Timestamps are: " + property1 + " " + property2);
				logger.warn("exception is: ", e);
			}catch(NumberFormatException e){
				logger.warn("Could not convert timestamps: bad format?  Timestamps are: " + property1 + " " + property2);
				logger.warn("exception is: ", e);
			}
			if(timestamp1 != null && timestamp2 != null)
				score = score + compareDate(timestamp1, timestamp2) * comparisonWeight;
		}
		//complaining that it is the array list, but function is working with jsonarray
		if (comparisonFunction.equals("compareReferences"))	{
			score = score + compareReferences(property1, property2) * comparisonWeight;	
		}
		if (comparisonFunction.equals("SmithWaterman"))	{
			SmithWaterman sw = new SmithWaterman();
			double newScore = sw.smithWatermanScore(property1.toString(), property2.toString());
			score = score + newScore * comparisonWeight;
		}

		if (comparisonFunction.equals("WHIRL"))	{
			whirl = new WHIRL();
			double w = whirl.compareObjects(property1.toString(), property2.toString());
			score = score + w * comparisonWeight;
		}

		//need to write one for whirl
		return score;
	}

	//return is between 0.0 (nothing in common) and 1.0
	static double compareReferences (Object o1, Object o2)	{

		if (o1 == null || o2 == null)	return 0.0;
		int match = 0, total = 0;

		ArrayList a1 = (ArrayList) o1;
		ArrayList a2 = (ArrayList) o2;
		total = a1.size() + a2.size();

		for (int i = 0; i < a1.size(); i ++)	{
			for (int j = 0; j < a2.size(); j++)	{
				if (a1.get(i).toString().equals(a2.get(j).toString()))	{
					match++;
					total--;
				}
			}
		}
		if(match == 0 ) 
			return 0;
		else
			return (double)(match)/(double)total;
	}

	public static double compareDate (long timeOne, long timeTwo)	{
		if (timeOne == timeTwo) return 1.0;
		else return 1.0/(double)Math.abs(timeOne - timeTwo);
	}

	/*
    public boolean findDuplicateVertex(String vertices)	{
		double maxScore = 0.0;
		String idOfDuplicateOne;
		String idOfDuplicateTwo;
		JSONObject graphson = new JSONObject(vertices);
		JSONArray jsonVerts = graphson.optJSONArray("vertices");

		if (jsonVerts != null)	{

			//creating two maps: existing graph, and new input
			// with key = "_id" and value = "description" for the WHIRL function								
			Map<String, String> descriptionExisting = getExistingVerticesDescriptionMap();
			Map<String, String> descriptionNew = getNewVerticesDescriptionMap(jsonVerts);
			whirl.setTextMaps(descriptionExisting, descriptionNew);

			Map<String, String> vertIDCache = align.getIDCache();

    		for (String idOne : vertIDCache.keySet())	{
    			double score = 0.0;
				Map<String, Object> existingVertex = align.getVertByID(vertIDCache.get(idOne).toString());

			for (int i = 0; i < jsonVerts.length(); i++)	{
				JSONObject newVertex = (JSONObject) jsonVerts.get(i);
				Map<String, Map<String, Object>> property = align.getConfig(newVertex);
    				for (Object s : newVertex.keySet()) {
    					if (existingVertex.get(s) != null) {
							if (property.get(s) != null)	{
								Map<String, Object> configProperties = (Map<String, Object>) property.get(s);
							// in bugtraq _id == CVE
							String idTwo = newVertex.get("CVE").toString();
    							score = Compare.comparisonScore (s.toString(), idOne, idTwo, existingVertex.get(s), newVertex.get(s.toString()), configProperties);

							//	if (maxScore < score)	{	
							//		score = maxScore;
						//		idOfDuplicate = idTwo;
   						//	}
						//	if (score > 0.75)	System.out.println("idOne = " + idOne + " idTwo = " + idTwo + " score = " + score);
							}
						}
    				}
				}
			}
		}
    		//set threshold	    		
    	//	if (maxScore > 0.75)	{	//=> duplicate;
    	//		Map<String, String> mergeMehods = computeMerchMethodMap (property);
    			//updating properties of duplicate based on config file
    	//		align.alignVertProps(idOfDuplicate, (Map<String, Object>) vertex, mergeMethods);	

		//}


    	return true;
    }
	 */

	/*
	//unneeded, everything in use is static...
	public Compare(Align align)	{
		this.align = align;
		this.logger = LoggerFactory.getLogger(Align.class);
		comparison = new Comparison();
		whirl = new WHIRL();
	}
	 */

	/*
	//setting map of existing descriptions keyed on id
	//unused
	Map<String, String>  getExistingVerticesDescriptionMap()	{

		Map<String, String> description = new HashMap<String, String>();	
		Map<String, String> vertIDCache = align.getIDCache();

	    for (String id : vertIDCache.keySet())	{ //TODO: can't assume cache will have all needed verts
			Map<String, Object> existingVertex = align.getVertByID(vertIDCache.get(id));
			if (existingVertex.get("description") != null)	
				description.put(id, existingVertex.get("description").toString());
		}
		return description;
	}
	 */

	/*
	//making map of descriptions keyed on id for new vertexes
	//unused
	Map<String, String> getNewVerticesDescriptionMap(JSONArray newVertex)	{

		Map<String, String> description = new HashMap<String, String>();
		JSONObject vertex = new JSONObject();

		for (int i = 0; i < newVertex.length(); i++)	{
			vertex = (JSONObject) newVertex.get(i);
			if (vertex.has("description") && vertex.has("_id"))	{
				String id = vertex.getString("_id");		
				description.put(id, vertex.getString("description"));
			}
		}

		return description;
	}
	 */

	/*
	//unused
	public Map<String, String> computeMergeMethodMap (Map<String, Map<String, Object>> property)	{

		Map<String, Object> temp = new HashMap<String, Object>();
		Map<String, String> mergeMethods = new HashMap<String, String>();
		String renewProperty;

		for (String key : property.keySet())	{
			temp = (Map<String, Object>) property.get(key);
			renewProperty = temp.get("resolutionFunction").toString();
			mergeMethods.put(key, renewProperty);
		}

		return mergeMethods;
	}
	 */

}
