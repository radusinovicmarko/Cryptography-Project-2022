package org.unibl.etf.crypto;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import org.bouncycastle.oer.its.SymmAlgorithm;
import org.bouncycastle.operator.OperatorCreationException;
import org.unibl.etf.crypto.quiz.Question;
import org.unibl.etf.crypto.quiz.User;
import org.unibl.etf.crypto.utils.CRLUtils;
import org.unibl.etf.crypto.utils.DigitalEnvelopeUtils;
import org.unibl.etf.crypto.utils.HashUtils;
import org.unibl.etf.crypto.utils.SteganographyUtils;
import org.unibl.etf.crypto.utils.SymmetricCryptographyUtils;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.effect.Reflection;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Pane;
import javafx.scene.text.Font;
import javafx.scene.text.Text;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class QuizWindow extends Application {
	
	public static final String questionsFolder = "./src/questions/";
	public static final String resultsPath = "./src/results/results.txt";
	public static final int numberOfQuestions = 5;
	private ArrayList<Question> questions = new ArrayList<>();
	private ArrayList<Object> nodes = new ArrayList<>();
	private User currentUser;
	private long startTime, endTime;
	private static boolean stopTime = false;
	private static int maxNumberOfEntries = 3;
	private Label resultLbl = new Label();

	@Override
	public void start(Stage stage) throws Exception {
		getQuestions();
		currentUser = Login.getUser();
		stage.setTitle("Kviz");
		BorderPane root = new BorderPane();
		GridPane centerPane = new GridPane();
		Label titleLbl = new Label("Kviz");
		titleLbl.setFont(new Font(18));
		Label timeLbl = new Label("");
		timeLbl.setFont(new Font(16));
		GridPane topPane = new GridPane();
		topPane.setPadding(new Insets(20, 1, 1, 30));
		topPane.setHgap(400);
		topPane.add(titleLbl, 0, 0);
		topPane.add(timeLbl, 1, 0);
		ScrollPane scrollPane = new ScrollPane();
		scrollPane.setContent(centerPane);
		root.setCenter(scrollPane);
		scrollPane.setPadding(new Insets(30, 20, 20, 20));
		root.setTop(topPane);
		centerPane.setAlignment(Pos.CENTER);
		centerPane.setHgap(20);
		centerPane.setVgap(10);
		centerPane.setPadding(new Insets(15, 50, 15, 10));
		int column = 0;
		for (int i = 0; i < questions.size(); i++) {
			Question question = questions.get(i);
			Label questionLbl = new Label();
			questionLbl.setWrapText(true);
			questionLbl.setText((i + 1) + ". " + question.getQuestion());
			centerPane.add(questionLbl, 0, column++);
			if (!question.hasMultipleAnswers()) {
				TextField tf = new TextField();
				centerPane.add(tf, 0, column++);
				nodes.add(tf);
			}
			else {
				ArrayList<RadioButton> radioBtns = new ArrayList<>();
				ToggleGroup group = new ToggleGroup();
				int j = 0;
				for (String option : question.getListOfAnswers()) { 
					radioBtns.add(new RadioButton());
					radioBtns.get(j).setText(option);
					radioBtns.get(j++).setToggleGroup(group);
				}
				for (RadioButton btn : radioBtns) 
					centerPane.add(btn, 0, column++);
				nodes.add(group);
			}
			centerPane.add(new Text(""), 0, column++);
		}
		Button finishBtn = new Button("Završi kviz");
		finishBtn.setOnAction(e -> { finishBtn.setDisable(true); finishQuiz(); });
		centerPane.add(finishBtn, 1, column++);
		centerPane.add(resultLbl, 0, column);
		Button showResultsBtn = new Button("Prikazi rezultate");
		showResultsBtn.setOnAction(e -> { showResultsAction(stage); });
		centerPane.add(showResultsBtn, 1, column);
		Scene scene = new Scene(root, 600, 600);
		stage.setResizable(false);
		stage.setScene(scene);
		Thread t = new Thread(() ->  {
			int h = 0, m = 0, s = 0;
			while (!stopTime) {
				String time = String.format("%d h %d m %d s", h, m, s);
				Platform.runLater(() -> {
					timeLbl.setText(time);
	            });
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e1) {
					e1.printStackTrace();
				}
				s++;
				if (s >= 60) {
					m++;
					s %= 60;
				}
				if (m >= 60) {
					h++;
					m %= 60;
				}
			}
		});
		stage.show();
		t.start();
		startTime = System.nanoTime();
	}
	
	private void finishQuiz() {
		
		endTime = System.nanoTime();
		stopTime = true;
		currentUser.incrementNumberOfEntries();
		int correctAnswers = 0, i = 0;
		for (Object o : nodes) {
			if (o instanceof TextField) {
				TextField tf = (TextField) o;
				if (tf.getText() != null && questions.get(i).checkAnswer(tf.getText()))
					correctAnswers++;
			}
			else {
				ToggleGroup tg = (ToggleGroup) o;
				RadioButton selected = (RadioButton) tg.getSelectedToggle();
				if (selected != null && questions.get(i).checkAnswer(selected.getText()))
					correctAnswers++;
			}
			i++;
		}
		currentUser.setPercetange((double)correctAnswers / numberOfQuestions * 100);
		currentUser.setElapsedTime(endTime - startTime); 
		resultLbl.setText("Rezultat: " + currentUser.toString());
		if (currentUser.getNumberOfEntries() >= maxNumberOfEntries)
			try {
				CRLUtils.revokeCertificate(currentUser.getCertificate());
			} catch (OperatorCreationException | CRLException e) {
				e.printStackTrace();
			}
		updateDB();
		updateResults();
	}

	private void showResultsAction(Stage stage) {
		Stage stage1 = new Stage();
		stage1.setTitle("Kviz");
		stage1.initModality(Modality.APPLICATION_MODAL);
		stage1.initOwner(stage);
		BorderPane root = new BorderPane();
		TextArea area = new TextArea();
		try {
			byte[] in = Files.readAllBytes(Paths.get(resultsPath));
			String s = new String(DigitalEnvelopeUtils.decrypt(in, SymmetricCryptographyUtils.symmetricKeyResultsPath));
			area.setText(s);
			area.setEditable(false);
			root.setCenter(area);
			Scene scene = new Scene(root, 300, 300);
			stage1.setScene(scene);
			stage1.show();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void showAlert(Stage stage, AlertType type, String header, String content) {
		Alert alert = new Alert(type);
		alert.setTitle("Alert");
		alert.setHeaderText(header);
		alert.setContentText(content);
		alert.showAndWait();
	}
	
	private void updateResults() {
		File resultsFile = new File(resultsPath);
		if (resultsFile.length() == 0) {
			try {
				DigitalEnvelopeUtils.createDigitalEnvelope(SymmetricCryptographyUtils.symmetricKeyResultsPath);
			} catch (Exception e1) {
				e1.printStackTrace();
			}
			try {
				String newContent = currentUser.toString();
				byte[] output = DigitalEnvelopeUtils.encrypt(newContent.getBytes(), SymmetricCryptographyUtils.symmetricKeyResultsPath);
				try (FileOutputStream fos = new FileOutputStream(resultsFile)) {
					fos.write(output);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		else {
			try {
				byte[] in = Files.readAllBytes(Paths.get(resultsPath));
				String s = new String(DigitalEnvelopeUtils.decrypt(in, SymmetricCryptographyUtils.symmetricKeyResultsPath));
				s += "\n" + currentUser.toString();
				byte[] output = DigitalEnvelopeUtils.encrypt(s.getBytes(), SymmetricCryptographyUtils.symmetricKeyResultsPath);
				try (FileOutputStream fos = new FileOutputStream(resultsFile)) {
					fos.write(output);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void updateDB() {
		try {
			List<String> dbEntries = Files.readAllLines(Paths.get(RegisterWindow.usersDBPath));
			List<String> newDBEntries = new ArrayList<>();
			for (int i = 0; i < dbEntries.size(); i++) {
				String entry = dbEntries.get(i);
				String userName = entry.split(";")[0];
				if (userName.equals(currentUser.getUserName())) {
					String password = entry.split(";")[1];
					int newNumberOfEntries = currentUser.getNumberOfEntries();
					newDBEntries.add(currentUser.getUserName() + ";" + password + ";" + newNumberOfEntries);
				}
				else
					newDBEntries.add(entry);
			}
			try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(RegisterWindow.usersDBPath))))) {
				for (String entry : newDBEntries)
					pw.println(entry);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void getQuestions() {
		int i = 0;
		Random rnd = new Random();
		while (i != numberOfQuestions) {
			int index = rnd.nextInt(20) + 1;
			try {
				byte[] out = SteganographyUtils.decodeBMP(new File(questionsFolder + "Quiz" + index + ".bmp"));
				String input = new String(DigitalEnvelopeUtils.decrypt(out, SymmetricCryptographyUtils.symmetricKeyStegoPath));
				Question question = new Question(input);
				if (!questions.contains(question)) {
					questions.add(question);
					i++;
				}
			} catch (Exception e) { e.printStackTrace();}
		}
	}
}
