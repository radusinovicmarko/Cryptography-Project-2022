package org.unibl.etf.crypto.quiz;

import java.security.cert.X509Certificate;

public class User {
	
	private String userName;
	private int numberOfEntries;
	private long elapsedTime;
	private double percentage;
	private X509Certificate certificate;
	
	public User(String userName, int numberOfEntries, X509Certificate certificate) {
		this.userName = userName;
		this.numberOfEntries = numberOfEntries;
		this.certificate = certificate;
	}
	
	public int getNumberOfEntries() {
		return numberOfEntries;
	}
	
	public void setPercetange(double percentage) {
		this.percentage = percentage;
	}
	
	public void setElapsedTime(long elapsedTime) {
		this.elapsedTime = elapsedTime;
	}
	
	public void incrementNumberOfEntries() {
		numberOfEntries++;
	}
	
	public String getUserName() {
		return userName;
	}
	
	public X509Certificate getCertificate() {
		return certificate;
	}
	
	@Override
	public String toString() {
		return String.format("%s\t%.4f [s]\t%.2f%%", userName, elapsedTime / 1000000000.0, percentage);
	}

}
