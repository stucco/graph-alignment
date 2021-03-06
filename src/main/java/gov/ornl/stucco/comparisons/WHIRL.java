package gov.ornl.stucco.comparisons;

import java.util.*;
//import java.util.stream.*;

public class WHIRL {
	private String[] s1;
	private String[] s2;
	private PorterStemmer ps;
	private Set<String> T;
	private Map<String, Integer> s1WordsCount;
	private Map<String, Integer> s2WordsCount;
	private String str;
	private double weightOne, weightTwo, dotProduct, similarity;
	private int count;

	public WHIRL ()	{
		ps = new PorterStemmer();
		T = new HashSet<String>();
		s1WordsCount = new HashMap<String, Integer>();
		s2WordsCount = new HashMap<String, Integer>();
		dotProduct = 0.0; 
		similarity = 0.0;
	}

	public double compareObjects (String stringOne, String stringTwo)	{	
		s1 = stringOne.split(" ");
		s2 = stringTwo.split(" ");

		for (String s : s1)	{
			if (RemoveStopWords.containsString(s)) continue;
			s = s.toLowerCase();	//converting strings to low case letters
			s = s.replaceAll ("\\W", " ").trim();	//removing chars
			ps.add(s.toCharArray(), s.length());
			ps.stem();
			str = ps.toString();
			T.add(str);	//making set of distinct words
			if (s1WordsCount.get(str) == null)	{	//counting words
				s1WordsCount.put(str, 1);
			}
			else	{
				count = s1WordsCount.get(str);
				s1WordsCount.put(str, ++count);
			}
		}
		for (String s : s2)	{
			if (RemoveStopWords.containsString(s)) continue;
			s = s.toLowerCase();
			s = s.replaceAll ("\\W", " ").trim();
			ps.add(s.toCharArray(), s.length());
			ps.stem();
			str = ps.toString();
			T.add(str);
			if (s2WordsCount.get(str) == null)	{
				s2WordsCount.put(str, 1);
			}
			else	{
				count = s2WordsCount.get(str);
				s2WordsCount.put(str, ++count);
			}
		}

		double sim = 0.0; 

		//System.out.println(s2WordsCount);
		//System.out.println(s1WordsCount);

		for (String s : T)	{

			if (s2WordsCount.get(s) != null && s1WordsCount.get(s) != null)	{
				count = 2;
				weightOne = Math.log10(s1WordsCount.get(s) + 1.0) * Math.log10(2/(double) count); 
				weightTwo = Math.log10(s2WordsCount.get(s) + 1.0) * Math.log10(2/(double) count); 
				dotProduct = dotProduct + s1WordsCount.get(s) * (double) s2WordsCount.get(s);
			}
			else if (s1WordsCount.get(s) == null)	{
				count = 1;
				weightOne = 0.0; 
				weightTwo = Math.log10(s2WordsCount.get(s) + 1.0) * Math.log10(2/(double) count); 
			}
			else 	{
				count = 1;
				weightOne = Math.log10(s1WordsCount.get(s) + 1.0) * Math.log10(2/(double) count); 
				weightTwo = 0.0; 
			}
			similarity = similarity + (weightOne * weightTwo); 
		}		
		similarity = similarity / dotProduct;		
		return similarity;
	}
}
/*
//	public static void main (String[] args)	{
//		new WHIRL(args);
//
	}
}*/
