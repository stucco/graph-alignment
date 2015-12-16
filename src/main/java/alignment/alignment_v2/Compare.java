package alignment.alignment_v2;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;
import org.json.JSONArray;

import alignment.alignment_v2.comparisons.WHIRL;
import alignment.alignment_v2.comparisons.CosineSimilarity;
import alignment.alignment_v2.comparisons.SmithWaterman;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.Attribute;

import org.apache.commons.lang.StringUtils;

public class Compare extends PreprocessSTIXwithJDOM2 {

	private CosineSimilarity cs = null;
	private WHIRL whirl = null;

	public double compareVertices(JSONObject vertexOne, JSONObject vertexTwo, JSONObject vertexOntology) {
		double score = 0.0;
		JSONObject properties = vertexOntology.getJSONObject("properties");
		
		for (Object propertyObject : properties.keySet()) {
			String property = propertyObject.toString();
			if (vertexOne.has(property) && vertexTwo.has(property)) {
				double newScore = compareProperties(vertexOne.get(property), vertexTwo.get(property), properties.getJSONObject(property));
				score = score + newScore;
			}
		}

	//	TODO: finish on xml comparison; do more testing
	//	double xmlComparisonScore = compareSourceDocuments(vertexOne.getString("sourceDocument"), vertexTwo.getString("sourceDocument"), vertexOntology);
		
		return score;
	}

	private double compareProperties(Object propertyOne, Object propertyTwo, JSONObject propertyOntology) {
		double comparisonWeight = propertyOntology.optDouble("comparisonWeight", 1.0);
		String comparisonFunction = propertyOntology.getString("comparisonFunction");
		if (comparisonFunction.equals("exact")) {
			return ((propertyOne.equals(propertyTwo)) ? 1.0 : 0.0) * comparisonWeight;
		}
		if (comparisonFunction.equals("WHIRL")) {
			//TODO After collecting big anough database, create config file for whirl and remove cosine similarity comparison; 
   			//     up until then, use greatest between cosine similarity and whirl
			whirl = (whirl == null) ? new WHIRL() : whirl;
			double whirlScore =  comparisonWeight * whirl.compareObjects(propertyOne.toString(), propertyTwo.toString());
			cs = (cs == null) ? new CosineSimilarity() : cs;
			double csScore = cs.getSimilarityScore(propertyOne.toString(), propertyTwo.toString());
			return (whirlScore > csScore) ? whirlScore : csScore;
		}
		if (comparisonFunction.equals("compareTimestamps"))	{
			//TODO: timestamps need to be standardized before this can happen
			// 	work on timestamp ... in stix it all is in xml GregorianCalendar format 
			Long timestampOne = null;
			Long timestampTwo = null;
		}
		//complaining that it is the array list, but function is working with jsonarray
		if (comparisonFunction.equals("compareReferences"))	{
			return compareReferences(propertyOne, propertyTwo) * comparisonWeight;	
		}
		if (comparisonFunction.equals("SmithWaterman"))	{
			SmithWaterman sw = new SmithWaterman();
			return sw.smithWatermanScore(propertyOne.toString(), propertyTwo.toString()) * comparisonWeight;
		}

		return 0.0;
	}
	
	//return is between 0.0 (nothing in common) and 1.0
	static double compareReferences (Object o1, Object o2)	{

		if (o1 == null || o2 == null) {
			return 0.0;
		}
		int match = 0;
		int total = 0;

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
		return (match == 0 ) ? 0 : ((double)match)/((double)total);
	}

	public static double compareDate (long timeOne, long timeTwo)	{
		return (timeOne == timeTwo) ? 1.0 : 1.0/(double)Math.abs(timeOne - timeTwo);
	}
	
	/* function compares two xml source documents traversing them along with relevant vertexOntology 
	   with comparison rules mapped to many of xml elements; if rule is not specified, algorithm is using 
	   a default comparison */
	private double compareSourceDocuments(String sourceDocOne, String sourceDocTwo, JSONObject vertexOntology) {
		double score = 0.0;
		Document docOne = parseXMLText(sourceDocOne);
		Document docTwo = parseXMLText(sourceDocTwo);
		Element rootElementOne = docOne.getRootElement();
		Element rootElementTwo = docTwo.getRootElement();
		JSONObject comparisonRules = vertexOntology.getJSONObject("comparisonRules").getJSONObject(rootElementOne.getName());
		score = compareDocumentElements(rootElementOne, rootElementTwo, comparisonRules);		

		return score;
	}

	/* compares two elements according comparisonRules from ontology specified for vertexTypes;	
	   function applies knows comparison rules to text fields of elements, if comparison rules do not specify, 
	   then it applies default comparison function */
	private double compareDocumentElements(Element elementOne, Element elementTwo, JSONObject comparisonRules) {
		double score = 0.0;
		printElement(elementOne);
		List<Element> childrenOne = elementOne.getChildren();
		// TODO: check if element contains an array of children elements with the same name ... it will make a difference
		for (Element childOne : childrenOne) {
			Element childTwo = null;
			if ((childTwo = elementTwo.getChild(childOne.getName(), childOne.getNamespace())) != null) {
				if (!childOne.getText().isEmpty() && !childTwo.getText().isEmpty()) {
					if (comparisonRules ==  null) {
						score = score + defaultComparison(childOne.getText(), childTwo.getText());
					} else {
						if (comparisonRules.has(childOne.getName())) {
							JSONObject comparisonSpecifications = comparisonRules.getJSONObject(childOne.getName());
							if (comparisonSpecifications.has("comparisonFunction")) {
								score = score + compareProperties(childOne.getText(), childTwo.getText(), comparisonSpecifications);
							} else {
								score = score + defaultComparison(childOne.getText(), childTwo.getText());
							}	
						}
					}
				} else {
					score = score + compareDocumentElements(childOne, childTwo, comparisonRules.optJSONObject(childOne.getName()));
				}
			}
		}		

		return score;
	}

	/* default comparison for values without specified comparison functions;
	   it is using exact comparison if both values are numeric, 
	   and cosine similarity if both values are strings */
	private double defaultComparison(String strOne, String strTwo) {
		if (StringUtils.isNumeric(strOne) && StringUtils.isNumeric(strTwo)) {
			return (strOne.equals(strTwo)) ? 1.0 : 0.0;
		} 
		if (!StringUtils.isNumeric(strOne) && !StringUtils.isNumeric(strTwo)) {
			cs = (cs == null) ? new CosineSimilarity() : cs;
			return cs.getSimilarityScore(strOne, strTwo);
		} 

		return 0.0;
	}
}
