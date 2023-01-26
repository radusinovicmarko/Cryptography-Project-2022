package org.unibl.etf.crypto;

import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.List;

import org.unibl.etf.crypto.utils.SteganographyUtils;
import org.unibl.etf.crypto.utils.SymmetricCryptographyUtils;
import org.unibl.etf.crypto.quiz.User;
import org.unibl.etf.crypto.utils.AsymmetricKeysUtils;
import org.unibl.etf.crypto.utils.CRLUtils;
import org.unibl.etf.crypto.utils.DigitalCertificateUtils;
import org.unibl.etf.crypto.utils.DigitalEnvelopeUtils;
import org.unibl.etf.crypto.utils.HashUtils;

import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.effect.Reflection;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class Login extends Application {

	public static final String defaultUploadFolder = "./src/PKI/";
	private static String userName = null;
	private static String password = null;
	private X509Certificate certificate = null;
	private static User user;
	
	@Override
	public void start(Stage stage) throws Exception {
		stage.setTitle("Prijava");
		GridPane gridPane = new GridPane();
		BorderPane root = new BorderPane();
		Label titleLbl = new Label("Prijava");
		titleLbl.setFont(new Font(18));
		titleLbl.setEffect(new Reflection());
		FlowPane topPane = new FlowPane(titleLbl);
		topPane.setPadding(new Insets(20, 1, 1, 30));
		root.setCenter(gridPane);
		root.setTop(topPane);
		gridPane.setAlignment(Pos.CENTER);
		gridPane.setHgap(10);
		gridPane.setVgap(10);
		gridPane.setPadding(new Insets(15, 15, 15, 15));
		Label userNameLbl = new Label("Korisnièko ime:");
		Label passLbl = new Label("Lozinka:");
		Label notRegistratedLbl = new Label("Niste registrovani?");
		TextField userNameTF = new TextField();
		PasswordField passPF = new PasswordField();
		Button loginBtn = new Button("Prijava");
		loginBtn.setOnAction(e -> { try {
			login(stage, userNameTF.getText(), passPF.getText());
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} });
		//loginBtn.setOnAction(e -> test());
		Button certBtn = new Button("Otpremite digitalni sertifikat");
		certBtn.setOnAction(e -> { certBtnAction(stage); });
		Label certLbl = new Label();
		Button registerBtn = new Button("Registracija");
		registerBtn.setOnAction(e -> {
			stage.hide();
			RegisterWindow window = new RegisterWindow();
			try {
				window.start(new Stage());
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		});
		gridPane.add(userNameLbl, 0, 0);
		gridPane.add(userNameTF, 1, 0);
		gridPane.add(passLbl, 0, 1);
		gridPane.add(passPF, 1, 1);
		gridPane.add(certBtn, 0, 3);
		gridPane.add(certLbl, 1, 3);
		gridPane.add(loginBtn, 1, 4);
		gridPane.add(notRegistratedLbl, 0, 5);
		gridPane.add(registerBtn, 1, 5);
		Scene scene = new Scene(root, 500, 300);
		stage.setResizable(false);
		stage.setScene(scene);
		stage.show();
	}

	public static void main(String[] args) throws IOException {
		launch(args);
	}
	
	private void test() {
		/*try {
			DigitalEnvelopeUtils.createDigitalEnvelope(SymmetricCryptographyUtils.symmetricKeyStegoPath);
		} catch (Exception e1) {
			e1.printStackTrace();
		}*/
		try {
			List<String> questions = Files.readAllLines(Paths.get("pitanja.txt"));
			for (int i = 1; i <= 20; i++) {
				byte[] in = DigitalEnvelopeUtils.encrypt(questions.get(i - 1).getBytes(), SymmetricCryptographyUtils.symmetricKeyStegoPath);
				SteganographyUtils.encodeBMP(new File("./test/test" + i + ".bmp"), in, i);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void login(Stage stage, String userName, String password) throws NoSuchAlgorithmException {
		if (certificate == null) {
			showAlert(stage, AlertType.ERROR, "Greška", "Digitalni sertifikat nije otpremljen.");
			return;
		}
		String passwordHash = HashUtils.getHash(password);
		try {
			List<String> users = Files.readAllLines(Paths.get(RegisterWindow.usersDBPath));
			if (users.stream().anyMatch(line -> line.split(";")[0].equals(userName) && line.split(";")[1].equals(passwordHash))) {
				String subjectName = certificate.getSubjectDN().getName();
				try {
					DigitalCertificateUtils.verifyCertficate(certificate);
				} catch (Exception e) {
					showAlert(stage, AlertType.ERROR, "Greška", "Nevalidan digitalni sertifikat.");
					return;
				}
				try {
					DigitalCertificateUtils.certificateValidity(certificate);
				} catch (Exception e) {
					showAlert(stage, AlertType.ERROR, "Greška", "Period važenja digitalnog sertifikata nije validan.");
					return;
				}
				if (CRLUtils.certificateRevoked(certificate)) {
					showAlert(stage, AlertType.ERROR, "Greška", "Digitalni sertifikat je povuèen.");
					return;
				}
				if (subjectName.substring(subjectName.indexOf("CN=") + 3).equals(userName)) {
					showAlert(stage, AlertType.INFORMATION, "Prijava", "Prijava uspješna!");
					users.stream().anyMatch(line -> {
						if (line.split(";")[0].equals(userName) && line.split(";")[1].equals(passwordHash)) {
							user = new User(line.split(";")[0], Integer.parseInt(line.split(";")[2]), certificate);
							return true;
						}
						return false;
					});
					stage.hide();
					QuizWindow quiz = new QuizWindow();
					quiz.start(new Stage());
				}
				else
					showAlert(stage, AlertType.ERROR, "Greška", "Neodgovarajuæi digitalni sertifikat.");
			} 
			else 
				showAlert(stage, AlertType.ERROR, "Greška", "Nevalidni podaci.");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void certBtnAction(Stage stage) {
		FileChooser chooser = new FileChooser();
		chooser.setTitle("Otpremite digitalni sertifikat");
		chooser.getExtensionFilters().addAll(new ExtensionFilter("Digital Certificate (*.der)", "*.der"),
											new ExtensionFilter("Digital Certificate (*.pem)", "*.pem"));
		chooser.setInitialDirectory(new File(defaultUploadFolder));
		File certFile = chooser.showOpenDialog(stage);
		if (certFile != null)
			certificate = DigitalCertificateUtils.readCertificate(certFile);
		if (certificate == null)
			showAlert(stage, AlertType.ERROR, "Greška", "Greška prilikom otpremanja digitalnog sertifikata! Pokušajte ponovo.");
	}

	private void showAlert(Stage stage, AlertType type, String header, String content) {
		Alert alert = new Alert(type);
		alert.setTitle("Alert");
		alert.setHeaderText(header);
		alert.setContentText(content);
		alert.showAndWait();
	}
	
	public static User getUser() {
		return user;
	}
}