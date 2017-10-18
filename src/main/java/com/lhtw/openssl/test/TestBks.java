package com.lhtw.openssl.test;

import com.lhtw.openssl.BksJksUtils;

public class TestBks {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			BksJksUtils.covertPFXtoBKS("C:\\Users\\Vince\\Desktop\\client\\cgwe.p12", "C:\\Users\\Vince\\Desktop\\client\\cgwe.bks", "",
					"");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
