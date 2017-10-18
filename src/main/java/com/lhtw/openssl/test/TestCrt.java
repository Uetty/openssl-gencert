package com.lhtw.openssl.test;

import com.lhtw.openssl.OpensslFactory;
import com.lhtw.openssl.OpensslUtils;

public class TestCrt {

	public static void main(String[] args) {
		String sofile = "/data/so/libLhtwSSL.so";	
		if(args.length >= 2 && !"".equals(args[1].trim())){
			sofile = args[1].trim();
		}
		OpensslUtils opensslUtils = OpensslFactory.createOpensslUtils(sofile);
//		System.out.println(opensslUtils.getPublicKey("/etc/pki/CA/ca.crt"));
		
		String basePath = "/etc/pki/CA/";
		String country = "CN";
		String stateOrProvince = "FJ";
		String locality = "FZ";
		String orgName = "lanhaitianwang";
		String orgUnitName = "lanhaitianwang";
		String commonName = "10.1.1.12";
		String clientName = "client399";
		if(args.length > 0 && !"".equals(args[0].trim())){
			clientName = args[0].trim();
		}
		String keyPath = basePath + clientName + ".key";
		String csrPath = basePath + clientName + ".csr";
		String crtPath = basePath + clientName + ".crt";
//		String p12Path = basePath + clientName + ".p12";
		String caKeyFile = "/etc/pki/CA/private/cakey.pem";
		String caCrtFile = "/etc/pki/CA/ca.crt";
		
		try{
		
			int result = 0;
			if((result = opensslUtils.jcreateClientCertificateCrt(1024, keyPath, 1, country, stateOrProvince, locality, orgName, orgUnitName, commonName,
					csrPath, caKeyFile, caCrtFile, 10 * 365 * 86400, crtPath)) > 0){
				System.out.println("resultcode ===> " + result);
				return;
			}
			System.out.println("resultcode ===> " + result);
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
