package alignment.alignment_v2.comparisons;

import java.util.*;

public class CosineSimilarity{

	private PorterStemmer ps;
	private Set<String> allWords;

	public CosineSimilarity()	{
		
		allWords = new HashSet<String>();
		ps = new PorterStemmer();
	}

	//removing suffixes from all words 
	public void  stemObjectAndAddToAllWordsMap (String s, Map<String, Integer> map)	{
		
		String[] str = s.split(" ");
		String substring, key;
		boolean done = false;
		int count;
	
		for (int j = 0; j < str.length; j++)  {
			if (RemoveStopWords.containsString(str[j])) continue;	//removing stop words
			str[j] = str[j].toLowerCase();    
			str[j] = str[j].replaceAll("\\W", "").trim();
			ps.add(str[j].toCharArray(), str[j].length());
			ps.stem();
			key = "#" + ps.toString() + "#";
			
                        for (int i = 0; i <= key.length() - 2; i++)  {
                                if (map.get(substring = key.substring(i, i + 2)) == null)	map.put(substring, 1);
				else	{
					count =  map.get(substring);
					map.put(substring, ++count); 
				}
				allWords.add(substring);
                        }
                }
	}

	//compares descriptions using WHIRL or cosine similarity
	public double getSimilarityScore (String s1, String s2)	{
											
		Map<String, Integer> mapOne = new HashMap <String, Integer>(); 	
		Map<String, Integer> mapTwo = new HashMap <String, Integer>(); 	
		
		double 	vDinominator = 0.0, uDinominator = 0.0, numerator = 0.0; 
				
		stemObjectAndAddToAllWordsMap(s1, mapOne);
		stemObjectAndAddToAllWordsMap(s2, mapTwo);
		
		double[] v = new double [allWords.size()];
		double[] u = new double [allWords.size()];
											
		calculateUOrV (mapOne, v);
		calculateUOrV (mapTwo, u);
		
		for (int k = 0; k < allWords.size(); k++)	{
			numerator = numerator + (v[k] * u[k]);
			vDinominator = vDinominator + (v[k] * v[k]); 
			uDinominator = uDinominator + (u[k] * u[k]);					
		}

		if (vDinominator == 0.0 | uDinominator == 0.0)	return 0.0;
		else	return numerator / (Math.sqrt(vDinominator) * Math.sqrt(uDinominator));
	}
	
	//helper function for compareDescriptions
	void calculateUOrV (Map <String, Integer> map, double[] array)	{
					
		int x = 0;
		for (String s : allWords)	{
		//	System.out.println(x);
			if (map.get(s) == null)	array[x] = 0.0;
			else array[x] = (double)map.get(s);
			x++;
		}					
	}
}
