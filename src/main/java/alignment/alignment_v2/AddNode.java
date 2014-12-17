package alignment.alignment_v2;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;
import org.slf4j.Logger;

import alignmentStudy.*;

public class AddNode {
	
	private Align align;
	private Logger logger;
	private Comparison comparison;
	private DateFormat dateTime;
	private WHIRL whirl;

	public AddNode(Align align)	{
		this.align = align;
		this.logger = align.getLogger();
		comparison = new Comparison();
		dateTime = new DateFormat();
		whirl = new WHIRL();
	}
	
	//setting map of existing descripitons keyed on id
	Map<String, String>  getExistingVerticesDescriptionMap()	{
	    	
		Map<String, String> description = new HashMap<String, String>();	
		Map<String, String> vertIDCache = align.getIDCache();
	    		
	    	for (String id : vertIDCache.keySet())	{
			Map<String, Object> existingVertex = align.getVertByID(vertIDCache.get(id));
			if (existingVertex.get("description") != null)	
				description.put(id, existingVertex.get("description").toString());
		}
		return description;
	}

	//making map of descripitons keyed on id for new vertexes
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
								
	public boolean findDuplicateVertex(String vertices)	{
    	
	    	try	{
			
	    		double maxScore = 0.0;
	    		String idOfDuplicateOne;
	    		String idOfDuplicateTwo;
	    		JSONObject graphson = new JSONObject(vertices);
			JSONArray jsonVerts = graphson.optJSONArray("vertices");
			
			if (jsonVerts != null)	{
				
				//creating two maps: exicting graph, and new input
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
		    							score = comparisonScore (s.toString(), idOne, idTwo, existingVertex.get(s), newVertex.get(s.toString()), configProperties);
	    								
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
	    		
		//	}
	    		
	    		
	    	}
	    	catch (JSONException e){
	    		logger.error("Exception!", e);
	    	}
	    	catch (Exception e)	{
	    		logger.error("Exception!", e);
	    	}
	    	return true;
	    }
	    
	public Map<String, String> computeMerchMethodMap (Map<String, Map<String, Object>> property)	{
			
			Map<String, Object> temp = new HashMap<String, Object>();
			Map<String, String> merchMethods = new HashMap<String, String>();
			String renewProperty;
			
			for (String key : property.keySet())	{
				temp = (Map<String, Object>) property.get(key);
				renewProperty = temp.get("resolutionFunction").toString();
				merchMethods.put(key, renewProperty);
			}
			
			return merchMethods;
		}
		
	public double comparisonScore (String propertyName, String idOne, String idTwo, Object property1, Object property2, Map<String, Object> configProperties) {
	    	
	    	Double score = 0.0;
		Double comparisonWeight = 1.0;
		String comparisonFunction = new String("");
	    	comparisonFunction = configProperties.get("comparisonFunction").toString();
	    	comparisonWeight = new Double (configProperties.get("comparisonWeight").toString());
	    	
	    	//was gonna use a switch statement, but switch with strings is not supported by eclipse
	    	if (comparisonFunction.equals("exact"))	{
	    		if (property1 == property2)	
	    			score = score + 1 * comparisonWeight;
	    	}
	    	//time should be standardized  
	    	if (comparisonFunction.equals("timeComparisonFunction"))	{
	    		score = score + comparison.compareDate(property1, property2) * comparisonWeight;
	    	//	score = score + compareDate(property1, property2) * comparisonWeight;
	    	}
	    //	complaining that it is the array list, but function is working with jsonarray
	   	if (comparisonFunction.equals("compareReferences"))	{
	    		score = score + comparison.compareReferences(property1, property2) * comparisonWeight;	
	    	}
	    	if (comparisonFunction.equals("SmithWaterman"))	{
	    		SmithWaterman sw = new SmithWaterman();
	    		double newScore = sw.smithWatermanScore(property1.toString(), property2.toString());
	    		score = score + newScore * comparisonWeight;
	    	}
		
		if (comparisonFunction.equals("WHIRL"))	{
			double w = whirl.getSimilarityScore(idOne, idTwo);
			score = score + w * comparisonWeight;
		}
			
	    	//need to write one for whirl
	    	return score;
	    }
	    
	    public double compareDate (Object time1, Object time2)	{
	    								
	    	long timeOne = dateTime.formatNVDDate(time1.toString());				
	    	long timeTwo = dateTime.formatBugtraqDate(time2.toString()); //change for different time format
	    												
	    	if (timeOne == timeTwo) return 1.0;
	    	else return 1.0/(double)Math.abs(timeOne - timeTwo);
	    }
}
