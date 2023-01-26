package org.unibl.etf.crypto;

import java.awt.Desktop;
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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.unibl.etf.crypto.utils.DigitalCertificateUtils;
import org.unibl.etf.crypto.utils.HashUtils;
import org.unibl.etf.crypto.utils.SymmetricCryptographyUtils;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.skin.TextFieldSkin;
import javafx.scene.effect.Bloom;
import javafx.scene.effect.DropShadow;
import javafx.scene.effect.Lighting;
import javafx.scene.effect.Reflection;
import javafx.scene.effect.Shadow;
import javafx.scene.image.Image;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.Text;
import javafx.stage.Modality;
import javafx.stage.Stage;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.x509.Extensions;

public class RegisterWindow extends Application {
	
	private TextField userNameTF = new TextField();
	private PasswordField passwordPF = new PasswordField();
	private PasswordField repeatPasswordPF = new PasswordField();
	private TextField organizationTF = new TextField("Elektrotehnicki fakultet");
	private TextField organizationalUnitTF = new TextField("CA_MarkoRadusinovic");
	private TextField localityTF = new TextField("Banja Luka");
	private TextField stateTF = new TextField("RS");
	private TextField countryTF = new TextField("BA");
	public static final String usersDBPath = "./src/database/UsersDB.txt";
	
	private List<TextField> textFields = List.of(userNameTF, passwordPF, repeatPasswordPF, organizationTF, organizationalUnitTF, localityTF, stateTF, countryTF);
	
	private Button registerBtn = new Button("Registracija");
	
	@Override
	public void start(Stage stage) throws Exception {
		stage.setTitle("Registracija");
		stage.setResizable(false);
		GridPane centerPane = new GridPane();
		BorderPane root = new BorderPane();
		Label titleLbl = new Label("Registracija");
		titleLbl.setFont(new Font(18));
		titleLbl.setEffect(new Reflection());
		FlowPane topPane = new FlowPane(titleLbl);
		topPane.setPadding(new Insets(20, 1, 1, 30));
		root.setCenter(centerPane);
		root.setTop(topPane);
		centerPane.setAlignment(Pos.CENTER);
		centerPane.setHgap(10);
		centerPane.setVgap(10);
		centerPane.setPadding(new Insets(15, 15, 15, 15));
		
		ArrayList<Label> labels = new ArrayList<>(Arrays.asList(new Label("Korisnièko ime*"), new Label("Lozinka*"), 
				new Label("Ponovite lozinku*"), new Label("Organizacija*"), new Label("Organizaciona jedinica*"), 
				new Label("Lokalitet*"), new Label("Region*"), new Label("Država*")));
		
		for (int i = 0; i < labels.size(); i++)
			centerPane.add(labels.get(i), 0, i);
		centerPane.add(userNameTF, 1, 0);
		centerPane.add(passwordPF, 1, 1);
		centerPane.add(repeatPasswordPF, 1, 2);
		centerPane.add(organizationTF, 1, 3);
		centerPane.add(organizationalUnitTF, 1, 4);
		centerPane.add(localityTF, 1, 5);
		centerPane.add(stateTF, 1, 6);
		centerPane.add(countryTF, 1, 7);
		centerPane.add(registerBtn, 1, 9);
		centerPane.add(new Label("* Polje je obavezno"), 0, 11);
		registerBtn.setOnAction(e -> { registerAction(stage); });
		
		Scene scene = new Scene(root, 400, 550);
		stage.setScene(scene);
		stage.setOnCloseRequest(e -> {
			stage.hide();
			Login window = new Login();
			try {
				window.start(new Stage());
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		});
		stage.show();
	}
	
	private void registerAction(Stage stage) {
		String userName = userNameTF.getText();
		String password = passwordPF.getText();
		if (textFields.stream().anyMatch(tf -> tf.getText().length() == 0)) {
			showAlert(stage, AlertType.ERROR, "Greška", "Niste popunili sva obavezna polja.");
			return;
		}
		if (!passwordPF.getText().equals(repeatPasswordPF.getText())) {
			showAlert(stage, AlertType.ERROR, "Greška", "Lozinke se ne poklapaju.");
			return;
		}
		if (!checkDB(userName)) {
			showAlert(stage, AlertType.ERROR, "Greška", "Korisnièko ime je zauzeto.");
			return;
		}
		Tuple<String, PrivateKey> tuple = null;
		try {
			tuple = DigitalCertificateUtils.createAndSignCertificateRequest(userName, password, 
						organizationTF.getText(), organizationalUnitTF.getText(), localityTF.getText(), stateTF.getText(), countryTF.getText());
		} catch (Exception e) {
			System.err.println(e.getMessage());
			showAlert(stage, AlertType.ERROR, "Greška", "Greška prilikom generisanja digitalnog sertifikata." );
			return;
		}
		String privateKeyPath = null;
		try {
			byte[] privateKeyEncrypted = SymmetricCryptographyUtils.encrypt(tuple.getSecond().getEncoded(), password);
			privateKeyPath = userName + "_PrivateKey.key";
			try (FileOutputStream fos = new FileOutputStream(new File(privateKeyPath))) {
				fos.write(privateKeyEncrypted);
			}
		} catch (Exception e) {
			System.err.println(e.getMessage());
			showAlert(stage, AlertType.ERROR, "Greška", "Greška prilikom registracije.");
			return;
		}
		try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(usersDBPath), true)))) {
			pw.println(userName + ";" + HashUtils.getHash(password) + ";0"); 
		} catch (IOException | NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			showAlert(stage, AlertType.ERROR, "Greška", "Greška prilikom registracije.");
			return;
		}
		try {
			showRegistrationInfo(stage, tuple.getFirst(), privateKeyPath);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void showRegistrationInfo(Stage stage, String certPath, String keyPath) throws IOException {
		Stage dialog = new Stage();
		dialog.setTitle("Registracija");
		dialog.initModality(Modality.APPLICATION_MODAL);
		dialog.initOwner(stage);
		GridPane centerPane = new GridPane();
		BorderPane root = new BorderPane();
		Label titleLbl = new Label("Registracija uspješna!");
		titleLbl.setFont(new Font(16));
		FlowPane topPane = new FlowPane(titleLbl);
		topPane.setPadding(new Insets(20, 1, 1, 30));
		root.setTop(topPane);
		root.setCenter(centerPane);
		centerPane.setAlignment(Pos.CENTER);
		centerPane.setHgap(10);
		centerPane.setVgap(10);
		centerPane.setPadding(new Insets(15, 15, 15, 15));
		centerPane.add(new Label("Putanja do digitalnog sertifikata:"), 0, 0);
		centerPane.add(new Label("Putanja do privatnog kljuèa:"), 0, 1);
		File certFile = new File(certPath);
		File keyFile = new File(keyPath);
		centerPane.add(new Label(certFile.getCanonicalPath()), 1, 0);
		centerPane.add(new Label(keyFile.getCanonicalPath()), 1, 1);
        Scene dialogScene = new Scene(root, 800, 200);
        dialog.setScene(dialogScene);
		dialog.show();
	}
	
	private boolean checkDB(String userName) {
		try {
			List<String> DBContent = Files.readAllLines(Paths.get(usersDBPath));
			return !DBContent.stream().anyMatch(line -> line.split(" ")[0].equals(userName));
		} catch (IOException e) {
			return false;
		} 
	}

	private void showAlert(Stage stage, AlertType type, String header, String content) {
		Alert alert = new Alert(type);
		alert.setTitle("Alert");
		alert.setHeaderText(header);
		alert.setContentText(content);
		alert.showAndWait();
	}

}
