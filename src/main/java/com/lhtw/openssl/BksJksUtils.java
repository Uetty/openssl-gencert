package com.lhtw.openssl;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * 
 * @author Vince
 * @email vincent_field@foxmail.com
 */
public class BksJksUtils {

	public static final String PKCS12 = "PKCS12";
	public static final String BKS = "BKS";
	public static final String JKS = "JKS";

	public static void covertPFXtoBKS(String p12File, String bksPath, String p12Pass, String bksPass) throws Exception {
		FileInputStream fis = null;
		try {
			KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
			fis = new FileInputStream(p12File);
			char[] srcPwd = p12Pass == null ? null : p12Pass.toCharArray();
			char[] destPwd = bksPass == null ? null : bksPass.toCharArray();
			inputKeyStore.load(fis, srcPwd);

			KeyStore outputKeyStore = KeyStore.getInstance(BKS,
					new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Enumeration<String> enums = inputKeyStore.aliases();
			while (enums.hasMoreElements()) {
				String keyAlias = (String) enums.nextElement();
				// System.out.println("alias=[" + keyAlias + "]");
				outputKeyStore.load(null, destPwd);
				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, srcPwd);
					java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
					outputKeyStore.setKeyEntry(keyAlias, key, destPwd, certChain);
				}
				// String fName = OUTPUT_KEYSTORE_FILE + "_" + keyAlias +
				// ".bks";
				FileOutputStream out = new FileOutputStream(bksPath);
				outputKeyStore.store(out, destPwd);
				out.close();
				outputKeyStore.deleteEntry(keyAlias);
			}
		} catch (Exception e) {
			throw e;
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void covertPFXtoJKS(String pfxPassword, String pfxFilePath, String jksPassword, String jksFilePath)
			throws Exception {
		FileInputStream fis = null;
		FileOutputStream out = null;
		try {
			// 加载PFX证书
			KeyStore inputKeyStore = KeyStore.getInstance(PKCS12);
			fis = new FileInputStream(pfxFilePath);
			char[] inPassword = pfxPassword == null ? null : pfxPassword.toCharArray();
			char[] outPassword = jksPassword == null ? null : jksPassword.toCharArray();
			inputKeyStore.load(fis, inPassword);

			KeyStore outputKeyStore = KeyStore.getInstance(JKS);
			outputKeyStore.load(null, outPassword);
			Enumeration<String> enums = inputKeyStore.aliases();
			while (enums.hasMoreElements()) {
				String keyAlias = enums.nextElement();
				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, inPassword);
					Certificate[] certChain = (Certificate[]) inputKeyStore.getCertificateChain(keyAlias);
					outputKeyStore.setKeyEntry(keyAlias, key, pfxPassword.toCharArray(),
							(java.security.cert.Certificate[]) certChain);
				}
			}
			out = new FileOutputStream(jksFilePath);
			outputKeyStore.store(out, outPassword);
		} catch (Exception e) {
			throw e;
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
				if (out != null) {
					out.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 从JKS格式转换为PKCS12格式
	 * 
	 * @param jksFilePath
	 *            String JKS格式证书库路径
	 * @param jksPasswd
	 *            String JKS格式证书库密码
	 * @param pfxFilePath
	 *            String PKCS12格式证书库保存文件夹
	 * @param pfxPasswd
	 *            String PKCS12格式证书库密码
	 */
	public static void covertJSKToPFX(String jksFilePath, String jksPasswd, String pfxFolderPath, String pfxPasswd)
			throws Exception {
		FileInputStream fis = null;
		try {
			KeyStore inputKeyStore = KeyStore.getInstance(JKS);
			fis = new FileInputStream(jksFilePath);
			char[] srcPwd = jksPasswd == null ? null : jksPasswd.toCharArray();
			char[] destPwd = pfxPasswd == null ? null : pfxPasswd.toCharArray();
			inputKeyStore.load(fis, srcPwd);

			KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
			Enumeration<String> enums = inputKeyStore.aliases();
			while (enums.hasMoreElements()) {
				String keyAlias = (String) enums.nextElement();
				// System.out.println("alias=[" + keyAlias + "]");
				outputKeyStore.load(null, destPwd);
				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, srcPwd);
					java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
					outputKeyStore.setKeyEntry(keyAlias, key, destPwd, certChain);
				}
			}
			FileOutputStream out = new FileOutputStream(pfxFolderPath);
			outputKeyStore.store(out, destPwd);
			out.close();
		} catch (Exception e) {
			throw e;
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 从BKS格式转换为PKCS12格式
	 * 
	 * @param jksFilePath
	 *            String JKS格式证书库路径
	 * @param jksPasswd
	 *            String JKS格式证书库密码
	 * @param pfxFilePath
	 *            String PKCS12格式证书库保存文件夹
	 * @param pfxPasswd
	 *            String PKCS12格式证书库密码
	 */
	public static void covertBKSToPFX(String jksFilePath, String jksPasswd, String pfxFolderPath, String pfxPasswd)
			throws Exception {
		FileInputStream fis = null;
		try {
			KeyStore inputKeyStore = KeyStore.getInstance(BKS,
					new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			fis = new FileInputStream(jksFilePath);
			char[] srcPwd = jksPasswd == null ? null : jksPasswd.toCharArray();
			char[] destPwd = pfxPasswd == null ? null : pfxPasswd.toCharArray();
			inputKeyStore.load(fis, srcPwd);

			KeyStore outputKeyStore = KeyStore.getInstance(PKCS12);
			Enumeration<String> enums = inputKeyStore.aliases();
			while (enums.hasMoreElements()) {
				String keyAlias = (String) enums.nextElement();
				System.out.println("alias=[" + keyAlias + "]");
				outputKeyStore.load(null, destPwd);
				if (inputKeyStore.isKeyEntry(keyAlias)) {
					Key key = inputKeyStore.getKey(keyAlias, srcPwd);
					java.security.cert.Certificate[] certChain = inputKeyStore.getCertificateChain(keyAlias);
					outputKeyStore.setKeyEntry(keyAlias, key, destPwd, certChain);
				}
			}
			FileOutputStream out = new FileOutputStream(pfxFolderPath);
			outputKeyStore.store(out, destPwd);
			out.close();
		} catch (Exception e) {
			throw e;
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 列出JKS库内所有X509证书的属性
	 * 
	 * @param jksFilePath
	 *            证书库路径
	 * @param jksPasswd
	 *            证书库密码
	 * @param algName
	 *            库类型
	 */
	public static void listAllCerts(String jksFilePath, String jksPasswd, String algName) {
		try {
			char[] srcPwd = jksPasswd == null ? null : jksPasswd.toCharArray();
			FileInputStream in = new FileInputStream(jksFilePath);
			KeyStore ks = KeyStore.getInstance(algName);
			ks.load(in, srcPwd);
			Enumeration<String> e = ks.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				java.security.cert.Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate X509Cert = (X509Certificate) cert;
					System.out.println("**************************************");
					System.out.println("版本号:" + X509Cert.getVersion());
					System.out.println("序列号:" + X509Cert.getSerialNumber().toString(16));
					System.out.println("主体名：" + X509Cert.getSubjectDN());
					System.out.println("签发者：" + X509Cert.getIssuerDN());
					System.out.println("有效期：" + X509Cert.getNotBefore());
					System.out.println("签名算法：" + X509Cert.getSigAlgName());
					System.out.println("输出证书信息:\n" + X509Cert.toString());
					System.out.println("**************************************");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * 列出BKS库内所有X509证书的属性
	 * 
	 * @param jksFilePath 证书库路径
	 * 
	 * @param jksPasswd 证书库密码
	 * 
	 * @param algName 库类型
	 */
	public static void listAllCertsBks(String jksFilePath, String jksPasswd, String algName) {
		try {
			char[] srcPwd = jksPasswd == null ? null : jksPasswd.toCharArray();
			FileInputStream in = new FileInputStream(jksFilePath);
			KeyStore ks = KeyStore.getInstance(algName, new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			ks.load(in, srcPwd);
			Enumeration<String> e = ks.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				java.security.cert.Certificate cert = ks.getCertificate(alias);
				if (cert instanceof X509Certificate) {
					X509Certificate X509Cert = (X509Certificate) cert;
					System.out.println("**************************************");
					System.out.println("版本号:" + X509Cert.getVersion());
					System.out.println("序列号:" + X509Cert.getSerialNumber().toString(16));
					System.out.println("主体名：" + X509Cert.getSubjectDN());
					System.out.println("签发者：" + X509Cert.getIssuerDN());
					System.out.println("有效期：" + X509Cert.getNotBefore());
					System.out.println("签名算法：" + X509Cert.getSigAlgName());
					System.out.println("输出证书信息:\n" + X509Cert.toString());
					System.out.println("**************************************");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
