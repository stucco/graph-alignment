package gov.ornl.stucco.alignment.comparisons;

//function is aligning two strings and retern similarity score based on local alignment
//it is an extension of edit distance and affine gap distance. 
//mismatches in the middle are the most important
//will identify "Jogh Brown" and "John B" as the same

public class SmithWaterman {
	private String s1;	//given strings
	private String s2;
	private String s1Aligned;	//aligned strings
	private String s2Aligned;
	private int[][] H;	//matrix for the best score calculation
	private int length1;	//lengths of the strings
	private int length2;
	private double similarityScore;
	private int maxI; 	//i index of the largest score in the metrix
	private int maxJ;	//j index of te largest score int he metrix

	public double smithWatermanScore (String str1, String str2)	{

		if (str1.equals(str2))	 return 1.0;       //checking if strings are the     same           

		length1 = str1.length();
		length2 = str2.length();
		s1 = new String (str1);
		s2 = new String (str2);
		s1Aligned = new String();
		s2Aligned = new String();

		H = new int [length1 + 1][length2 + 1];

		maxI = 0;
		maxJ = 0;

		matrixInitialization();
		scoreCalculation();
		setSimilarityScore();
		//	traceback();
		//	printAlignment();

		return similarityScore;
	}
	//firts row and column must be initialized to 0
	void matrixInitialization()	{

		for (int i = 0; i <= length1; i++)
			H[i][0] = 0;
		for (int i = 0; i <= length2; i++)
			H[0][i] = 0;
	}
	//filing up H matrix
	void scoreCalculation()	{

		for (int i = 1; i <= length1; i++)	{
			for (int j = 1; j <= length2; j++)	{	
				int matchMismatch = H[i-1][j-1] + score(s1.charAt(i-1), s2.charAt(j-1));
				int deletion = H[i-1][j] + score(s1.charAt(i-1), '-');
				int insertion =  H[i][j-1] + score('-', s2.charAt(j-1));
				H[i][j] = max(matchMismatch, deletion, insertion, 0);
				//	System.out.println(H[i][j]);
				if (H[i][j] > H[maxI][maxJ]) {
					maxI = i;	//saving the best value (max value)
					maxJ = j;
				}
			}	
		}
	}
	//return 2 points if chars are the same, and -1 if not
	int score (char a, char b)	{

		int r;

		if (a == b)	r = 2;
		else r = -1;
		//		System.out.println(a + " " + b + " " + r);

		return r;
	}

	//max int between four ints
	int max (int a, int b, int c, int d)	{

		return Math.max (Math.max(a, b), Math.max(c, d));
	}

	//similarity score is the bigest score in H matrix
	void setSimilarityScore()	{

		similarityScore = normalized(H[maxI][maxJ]);
	}

	double normalized (int score)	{

		return (double)score/((double)Math.max(length1, length2) * 2);
	}

	//traceback to compose an alignment strings
	void traceback ()	{
		int i = maxI;
		int j = maxJ;

		while (i > 0 && j > 0)	{
			if (i > 0 && j > 0 &&H[i][j] == H[i-1][j-1] + score(s1.charAt(i-1), s2.charAt(j-1)))	{
				s1Aligned = s1.charAt(i-1) + s1Aligned;	
				s2Aligned = s2.charAt(j-1) + s2Aligned;
				i--;
				j--;
				continue;
			}
			else if (i > 0 && H[i][j] == H[i-1][j] + score(s1.charAt(i-1), '-'))	{
				s1Aligned = s1.charAt(i-1) + s1Aligned;
				s2Aligned = '-' + s2Aligned;
				i--;
				continue;
			}
			else if (j > 0 && H[i][j] ==  H[i][j-1] + score('-', s2.charAt(j-1)))	{
				s1Aligned = '-' + s1Aligned;
				s2Aligned = s2.charAt(j - 1) + s2Aligned;
				j--;
				continue;
			}
			else if (H[i][j] == 0)	{
				s1Aligned = '-' + s1Aligned;
				s2Aligned = '-' + s2Aligned;
				i--;
				j--;
			}	
		}	
	}

	void printAlignment ()	{

		System.out.println(s1Aligned);
		System.out.println(s2Aligned);
	}

	void printMatrix ()	{

		for (int i = 0; i < length1; i++)	{
			for (int j = 0; j < length2; j++)	{
				System.out.print(H[i][j] + " ");
			}
			System.out.println();
		}
	}

	String getAlignedStrOne ()	{

		return s1Aligned;
	}

	String getAlignedStrTwo ()	{

		return s2Aligned;
	}
}
