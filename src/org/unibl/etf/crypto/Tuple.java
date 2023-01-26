package org.unibl.etf.crypto;

public class Tuple<T, V> {
	
	private T first;
	private V second;
	
	public Tuple(T first, V second) {
		this.first = first;
		this.second = second;
	}
	
	public T getFirst() {
		return first;
	}
	
	public V getSecond() {
		return second;
	}
}
