package org.unibl.etf.crypto.quiz;

import java.util.ArrayList;
import java.util.Arrays;

public class Question {
	
	private String question;
	private String rightAnswer;
	private ArrayList<String> answersList = null;
	private boolean multipleAnswers = false;
	
	public Question(String input) {
		String inputArray[] = input.split("#");
		if (inputArray.length == 3) {
			multipleAnswers = true;
			answersList = new ArrayList<>(Arrays.asList(inputArray[2].split(",")));
		} 
		question = inputArray[0];
		rightAnswer = inputArray[1];
	}
	
	public String getQuestion() {
		return question;
	}
	
	public ArrayList<String> getListOfAnswers() {
		return answersList;
	}
	
	public boolean hasMultipleAnswers() {
		return multipleAnswers;
	}
	
	public boolean checkAnswer(String givenAnswer) {
		return rightAnswer.toUpperCase().equals(givenAnswer.toUpperCase());
	}
	
	@Override 
	public boolean equals(Object other) {
		if (!(other instanceof Question))
			return false;
		Question otherQuestion = (Question)other;
		return question.equals(otherQuestion.question);
	}
}
