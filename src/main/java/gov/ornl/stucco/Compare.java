package gov.ornl.stucco;

import gov.ornl.stucco.preprocessors.PreprocessSTIX;
import gov.ornl.stucco.comparisons.CosineSimilarity;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import java.lang.Math;

import org.json.JSONObject;
import org.json.JSONArray;

import java.text.ParseException; 
import java.text.SimpleDateFormat;

import org.apache.commons.lang.math.NumberUtils;

import javax.xml.bind.DatatypeConverter; 

/**
 * Comparing two jsons by their fields.
 *
 * @author Maria Vincent
 */

public class Compare extends PreprocessSTIX {

	private static final String uuidPattern = "\\S+[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}";
	private CosineSimilarity cs = null;
	private double threshold = 0.0;

	public double compareVertices(JSONObject vertexOne, JSONObject vertexTwo, JSONObject vertexOntology) {
		int propertiesCount = 0;
		double totalScore = 0.0;
		for (Object key : vertexOne.keySet()) {
			String property = key.toString();
			if (vertexTwo.has(property)) {
				switch(property) {
					case "sourceDocument":
						String sourceDoc1 = vertexOne.getString("sourceDocument").replaceAll("<.+?>", " ");
						String sourceDoc2 = vertexTwo.getString("sourceDocument").replaceAll("<.+?>", " ");
						totalScore += defaultComparison(sourceDoc1, sourceDoc2);
						break;
					case "name":
						// this is a case when name was not found and id was placed instead, which is in most cases is not going to match
						// if they match, return 1.0 for the function
						String name1 = vertexOne.getString("name");
						String name2 = vertexTwo.getString("name");
						if (name1.matches(uuidPattern) || name2.matches(uuidPattern)) {
							if (name1.equals(name2)) {
								totalScore += 1.0;
							} else {
								continue;
							}
						}
						totalScore += defaultComparison(name1, name2);
						break;
					case "publishedDate": 
						String date1 = vertexOne.getString("publishedDate");
						String date2 = vertexTwo.getString("publishedDate");
						totalScore += compareDate(date1, date2);
						break;
					default:
						totalScore += defaultComparison(vertexOne.get(property).toString(), vertexTwo.get(property).toString());
						break;
				}	 
				propertiesCount++;
			}
		}	

		return (propertiesCount == 0) ? 0.0 : (double)totalScore/propertiesCount;
	}
	
	private static double compareDate (String timeOne, String timeTwo) {
		String format = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
		try {
			SimpleDateFormat df = new SimpleDateFormat(format);
  			return compareDate(df.parse(timeOne).getTime(), df.parse(timeTwo).getTime());

		} catch	(ParseException e)	{
			e.printStackTrace();
		}
  		return 0.0;	
	}

	public static double compareDate (long time1, long time2) {

		long days1 = TimeUnit.MILLISECONDS.toDays(time1);
		long days2 = TimeUnit.MILLISECONDS.toDays(time2);
	
		return Math.pow(Math.E, -(Math.pow(Math.abs(days1 - days2), 2)/20.0));	
	}

	/* 
	 *	default comparison for values without specified comparison functions;
	 *	it is using exact comparison if both values are numeric, 
	 *	and cosine similarity if both values are strings 
	 */
	public double defaultComparison(String strOne, String strTwo) {
		if (NumberUtils.isNumber(strOne) && NumberUtils.isNumber(strTwo)) {
			return (strOne.equals(strTwo)) ? 1.0 : 0.0;
		} else {
			cs = (cs == null) ? new CosineSimilarity() : cs;
			double score = cs.getSimilarityScore(strOne, strTwo);
			
			return (score > threshold) ? 1.0 : score;
		} 
	}

	public double compareSets(Set set, JSONArray array) {
		int overlap = 0;
		int minLength = Math.min(set.size(), array.length());
		for (int i = 0; i < array.length(); i++) {
			if (set.contains(array.get(i))) {
				overlap++;
			}
		}

		return (minLength == 0) ? 0.0 : (double)overlap/minLength;
	}
}
