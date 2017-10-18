package com.lhtw.openssl;

public class OpensslFactory {

	protected static String soPath = "";
	
//	private static Object sync = new Object();
	
	public static OpensslUtils createOpensslUtils(String location){
//		if(soPath == null || "".equals(soPath)){
//			synchronized (sync) {
				if(soPath == null || "".equals(soPath)){
					soPath = location;
				}
//			}
//		}
		return new OpensslUtils();
	}
}
