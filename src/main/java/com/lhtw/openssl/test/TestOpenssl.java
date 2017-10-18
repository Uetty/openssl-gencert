package com.lhtw.openssl.test;

import com.lhtw.openssl.OpensslFactory;
import com.lhtw.openssl.OpensslUtils;
/**
 * 
 * @author Vince
 *	@email vincent_field@foxmail.com
 */
public class TestOpenssl {

	public static void main(String[] args) {
		OpensslUtils opensslUtils = OpensslFactory.createOpensslUtils("/data/so/libLhtwSSL.so");
//		System.out.println(opensslUtils.getPublicKey("/etc/pki/CA/ca.crt"));
//		/data/so/libLhtwSSL.so
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
		String keyPath = "/etc/pki/CA/" + clientName + ".key";
		String csrPath = "/etc/pki/CA/" + clientName + ".csr";
		String crtPath = "/etc/pki/CA/" + clientName + ".crt";
		String p12Path = "/etc/pki/CA/" + clientName + ".p12";
		String caKeyFile = "/etc/pki/CA/private/cakey.pem";
		String caCrtFile = "/etc/pki/CA/ca.crt";
		
		try{
		
			int result = 0;
			if((result = opensslUtils.jcreateClientCertificateP12(1024, keyPath, 1, country, stateOrProvince, locality, orgName, orgUnitName, commonName,
					csrPath, caKeyFile, caCrtFile, 10 * 365 * 86400, crtPath, "753fe094b2d2ab269b41ad2ba94dce30ecfb65a6","", p12Path)) > 0){
				System.out.println("resultcode ===> " + result);
				return;
			}
			System.out.println("resultcode ===> " + result);
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
