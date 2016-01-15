package alignment.alignment_v2;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.json.JSONArray;

import alignment.alignment_v2.comparisons.WHIRL;
import alignment.alignment_v2.comparisons.CosineSimilarity;
import alignment.alignment_v2.comparisons.SmithWaterman;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Namespace;
import org.jdom2.Attribute;
import org.jdom2.Content;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.commons.lang.math.NumberUtils;

import javax.xml.bind.DatatypeConverter;

public class Compare extends PreprocessSTIXwithJDOM2 {

	private CosineSimilarity cs = null;
	private WHIRL whirl = null;
	private int propertiesCount;
	private int count;
	private double threshold = 0.75;

	public class Return {
		int count;
		double score;
		
		public Return() {
			count = 0;
			score = 0.0;
		}
	}

	public double compareVertices(JSONObject vertexOne, JSONObject vertexTwo, JSONObject vertexOntology) {
		Return comparisonReturn = new Return();
		if (vertexOntology == null) {
			for (Object key : vertexOne.keySet()) {
				String property = key.toString();
				if (property.equals("sourceDocument") || property.equals("name")) {
					continue;
				} else if (vertexOne.has(property) && vertexTwo.has(property)) {
					Return compReturn = new Return();
					compReturn.score = defaultComparison(vertexOne.get(property).toString(), vertexTwo.get(property).toString());
					comparisonReturn.score += compReturn.score;
					comparisonReturn.count += 1;	 
				}
			}	
		} else {
			JSONObject properties = vertexOntology.getJSONObject("properties");
			for (Object propertyObject : properties.keySet()) {
				String property = propertyObject.toString();
				if (vertexOne.has(property) && vertexTwo.has(property)) {
					Return compReturn = compareContent(vertexOne.get(property), vertexTwo.get(property), properties.getJSONObject(property));
					comparisonReturn.score += compReturn.score;
					comparisonReturn.count += compReturn.count;	 
				}
			}
		}
		Return xmlComparisonReturn = compareSourceDocuments(vertexOne.getString("sourceDocument"), vertexTwo.getString("sourceDocument"), vertexOntology);
		comparisonReturn.score = comparisonReturn.score + xmlComparisonReturn.score;
		comparisonReturn.count = comparisonReturn.count + xmlComparisonReturn.count;

		return (comparisonReturn.count == 0.0) ? 0.0 : comparisonReturn.score/comparisonReturn.count;
	}

	private Return compareContent(Object propertyOne, Object propertyTwo, JSONObject propertyOntology) {
		Return comparisonReturn = new Return();
		//TODO: revisit comparisonWeight and threshold
	//	double comparisonWeight = propertyOntology.optDouble("comparisonWeight", 1.0);
		double comparisonWeight = 1.0;
		String comparisonFunction = propertyOntology.optString("comparisonFunction");
		if (comparisonFunction.equals("exact")) {
			comparisonReturn.score = ((propertyOne.toString().equals(propertyTwo.toString())) ? 1.0 : 0.0) * comparisonWeight;
			comparisonReturn.count++;
			return comparisonReturn;
		}
		if (comparisonFunction.equals("WHIRL")) {
			//TODO After collecting big anough database, create config file for whirl and remove cosine similarity comparison; 
   			//     up until then, use greatest between cosine similarity and whirl
			whirl = (whirl == null) ? new WHIRL() : whirl;
			double whirlScore =  whirl.compareObjects(propertyOne.toString(), propertyTwo.toString());
			cs = (cs == null) ? new CosineSimilarity() : cs;
			double csScore = cs.getSimilarityScore(propertyOne.toString(), propertyTwo.toString());
			comparisonReturn.score = ((whirlScore > 0.75) ||  (csScore > 0.75)) ? 1.0 : (whirlScore > csScore) ? whirlScore : csScore;
			comparisonReturn.count++;
			return comparisonReturn;
		}
		if (comparisonFunction.equals("compareTimestamps"))	{
			double timeScore = compareDate(propertyOne.toString(), propertyTwo.toString());
			comparisonReturn.score = timeScore;
			comparisonReturn.count++;
			return comparisonReturn;	
	
		}
		//complaining that it is the array list, but function is working with jsonarray
		if (comparisonFunction.equals("compareReferences"))	{
			comparisonReturn.score = defaultComparison(propertyOne.toString(), propertyTwo.toString()) * comparisonWeight;
			comparisonReturn.count++;
			return comparisonReturn;
		}
		if (comparisonFunction.equals("SmithWaterman"))	{
			SmithWaterman sw = new SmithWaterman();
			comparisonReturn.score = sw.smithWatermanScore(propertyOne.toString(), propertyTwo.toString()) * comparisonWeight;
			comparisonReturn.count++;
			return comparisonReturn;
		}

		return new Return();
	}
	
	private static double compareDate (String timeOne, String timeTwo) {
		String format = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
		Date date = new Date();
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

	/* function compares two xml source documents traversing them along with relevant vertexOntology 
	   with comparison rules mapped to many of xml elements; if rule is not specified, algorithm is using 
	   a default comparison */
	private Return compareSourceDocuments(String sourceDocOne, String sourceDocTwo, JSONObject vertexOntology) {
		Document docOne = parseXMLText(sourceDocOne);
		Document docTwo = parseXMLText(sourceDocTwo);
		Element rootElementOne = docOne.getRootElement();
		Element rootElementTwo = docTwo.getRootElement();
		Return comparisonReturn = new Return();
		if (vertexOntology == null) {
			comparisonReturn = compareDocumentElements(rootElementOne, rootElementTwo, null);		
		} else {
			JSONObject comparisonRules = vertexOntology.getJSONObject("comparisonRules").getJSONObject(rootElementOne.getName());
			comparisonReturn = compareDocumentElements(rootElementOne, rootElementTwo, comparisonRules);		
		}	
		return comparisonReturn;
	}

	/* compares elements with default comparison for all the properties */
	public double compareDocumentElements(Element elementOne, Element elementTwo) {
		Return comparisonReturn = compareDocumentElements(elementOne, elementTwo, null);

		return (comparisonReturn.count == 0) ? 0.0 : comparisonReturn.score/comparisonReturn.count;
	}

	/* function determines if elements are complex (contains children) or contain text */
	private Return compareDocumentElements(Element elementOne, Element elementTwo, JSONObject comparisonRules) {
		// TODO: decide on maybe comparing referenced elements also, to see if elements have the same references
		if (elementOne.getAttribute("idref") != null || elementOne.getAttribute("object_reference") != null ||
			elementTwo.getAttribute("idref") != null || elementTwo.getAttribute("object_reference") != null ||
			elementOne.getName().equals("Relationship") || elementTwo.getName().equals("Relationship")) {
			return new Return();
		}
		if (!elementOne.getTextNormalize().isEmpty() || !elementTwo.getTextNormalize().isEmpty()) {
			return compareElements(elementOne, elementTwo, comparisonRules);
		} else {
			Return totalReturn = new Return();
			Map<String, Namespace> tagMapOne = getTagMap(elementOne);
			Map<String, Namespace> tagMapTwo = getTagMap(elementTwo);

			for (String tag : tagMapOne.keySet()) {
				if (tagMapTwo.containsKey(tag)) {
					List<Element> childrenOne = elementOne.getChildren(tag, tagMapOne.get(tag));
					List<Element> childrenTwo = elementTwo.getChildren(tag, tagMapTwo.get(tag));
					Return comparisonReturn = null;
				
					if (childrenOne.size() > 1 || childrenTwo.size() > 1) {
						comparisonReturn = compareElementList(childrenOne, childrenTwo, comparisonRules);
					} else {
						if (comparisonRules == null) {
							comparisonReturn = compareDocumentElements(childrenOne.get(0), childrenTwo.get(0), null);
						} else {	
							comparisonReturn = compareDocumentElements(childrenOne.get(0), childrenTwo.get(0), comparisonRules.optJSONObject(tag));
						}
					}
					totalReturn.count += comparisonReturn.count;
					totalReturn.score += comparisonReturn.score;
				}
			}
			
			return totalReturn;
		}
	}

	/* determines what function should be used to compare elements */
	private Return compareElements(Element elementOne, Element elementTwo, JSONObject comparisonRules) {
		Return totalReturn = new Return();
		if (comparisonRules ==  null) {
			totalReturn.score = defaultComparison(elementOne.getTextNormalize(), elementTwo.getTextNormalize());
			totalReturn.count++;
		} else {
			String comparisonFunction = (comparisonRules == null) ? null : comparisonRules.optString("comparisonFunction");
			if (comparisonFunction == null) {
				totalReturn.score = defaultComparison(elementOne.getTextNormalize(), elementTwo.getTextNormalize());
				totalReturn.count++;
			} else {
				totalReturn = compareContent(elementOne.getTextNormalize(), elementTwo.getTextNormalize(), comparisonRules);
			} 
		}
	
		return totalReturn;
	}
				
	/* compares list of elements with the same name */
	private Return compareElementList(List<Element> childrenOne, List<Element> childrenTwo, JSONObject comparisonRules) {
		int listOneSize = childrenOne.size();
		int listTwoSize = childrenTwo.size();
		int totalSize = listOneSize + listTwoSize;
		Return[][] scoreBoard = new Return[listOneSize][listTwoSize];
		Return totalScore = new Return();
		for (int i = 0; i < childrenOne.size(); i++) {
			Element childOne = childrenOne.get(i);
			String childName = childOne.getName();
			JSONObject comparisonRulesContent = (comparisonRules == null) ? null : comparisonRules.optJSONObject(childName);
			for (int j = 0; j < childrenTwo.size(); j++) {
				Element childTwo = childrenTwo.get(j);
				Return compReturn = compareDocumentElements(childOne, childTwo, comparisonRulesContent);
				scoreBoard[i][j] = compReturn;
			}
		}

		for (int i = 0; i < listOneSize; i++) {	
			double score = 0.0;
			int index = 0;
			for (int j = 0; j < listTwoSize; j++) {	
				if (score < scoreBoard[i][j].score) {
					score = scoreBoard[i][j].score;
					index = j;
				}
			}
			if (score > threshold) {
				totalScore.score = totalScore.score + scoreBoard[i][index].score;
				totalScore.count = totalScore.count + scoreBoard[i][index].count;
			}
		}

		return totalScore;
	}

	/* makes a map of element name and element namespace; used to find all the names, 
	   to determine if it is a single element with particular name or list */
	public static Map<String, Namespace> getTagMap(Element element) {
		Map<String, Namespace> tagMap = new HashMap<String, Namespace>();
		List<Element> children = element.getChildren();
		for (Element child : children) {
			tagMap.put(child.getName(), child.getNamespace());
		}

		return tagMap;
	}

	/* default comparison for values without specified comparison functions;
	   it is using exact comparison if both values are numeric, 
	   and cosine similarity if both values are strings */
	public double defaultComparison(String strOne, String strTwo) {
		if (NumberUtils.isNumber(strOne) && NumberUtils.isNumber(strTwo)) {
			return (strOne.equals(strTwo)) ? 1.0 : 0.0;
		} else {
			cs = (cs == null) ? new CosineSimilarity() : cs;
			double score = cs.getSimilarityScore(strOne, strTwo);
			
			return (score > threshold) ? 1.0 : score;
		} 
	}
}
