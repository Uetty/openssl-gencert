package com.lhtw.openssl;

/**
 * 
 * @author Vince
 *	@email vincent_field@foxmail.com
 */
public class OpensslUtils {

	static{
		System.load(OpensslFactory.soPath);
	}
	
	private static Object sync = new Object();
	
	protected OpensslUtils(){
	}
	
	private native String getPrivateKey(String keyFile);
	
	private native String getPublicKey(String keyFile);
	
	
	private native int opensslGenrsa(int keySize,String keyPath);
	
	/**
	 * 1:sha1,2:md2,4:md4,5:md5,224:sha224,256:sha256,384:sha384,512:sha512
	 */
	private native int opensslReq(String keyFile, int evpMode,String country,String stateOrProvince,String locality,String orgName,String orgUnitName,String commonName,String csrPath);
	
	private native int opensslCa(String caKeyFile,String caCrtFile,String csrFile,long term,String crtPath, int evpMode);
	
	private native int opensslPkcs12(String keyFile,String crtFile,String name, String pass, String p12Path);
	
	private native int createClientCertificateP12(int keySize,String keyPath,int evpMode,String country,String stateOrProvince,String locality,String orgName,
			String orgUnitName,String commonName,String csrPath,String caKeyFile,String caCrtFile,long term,String crtPath,String name,String pass, String p12Path);
	
	public native int createClientCertificateCrt(int keySize,String keyPath,int evpMode,String country,String stateOrProvince,String locality,String orgName,
			String orgUnitName,String commonName,String csrPath,String caKeyFile,String caCrtFile,long term,String crtPath);
	
	
	public String jgetPrivateKey(String keyFile){
		synchronized (sync) {
			return getPrivateKey(keyFile);
		}
	}
	
	public String jgetPublicKey(String keyFile){
		synchronized (sync) {
			return getPublicKey(keyFile);
		}
	}
	
	public int jopensslGenrsa(int keySize,String keyPath){
		synchronized (sync) {
			return opensslGenrsa(keySize, keyPath);
		}
	}
	
	/**
	 * 1:sha1,2:md2,4:md4,5:md5,224:sha224,256:sha256,384:sha384,512:sha512
	 */
	public int jopensslReq(String keyFile, int evpMode,String country,String stateOrProvince,String locality,String orgName,String orgUnitName,String commonName,String csrPath){
		synchronized (sync) {
			return opensslReq(keyFile, evpMode, country, stateOrProvince, locality, orgName, orgUnitName, commonName, csrPath);
		}
	}
	
	public int jopensslCa(String caKeyFile,String caCrtFile,String csrFile,long term,String crtPath, int evpMode){
		synchronized (sync) {
			return opensslCa(caKeyFile, caCrtFile, csrFile, term, crtPath, evpMode);
		}
	}
	
	public int jopensslPkcs12(String keyFile,String crtFile,String name, String pass, String p12Path){
		synchronized (sync) {
			return opensslPkcs12(keyFile, crtFile, name, pass, p12Path);
		}
	}
	
	public int jcreateClientCertificateP12(int keySize,String keyPath,int evpMode,String country,String stateOrProvince,String locality,String orgName,
			String orgUnitName,String commonName,String csrPath,String caKeyFile,String caCrtFile,long term,String crtPath,String name,String pass, String p12Path){
		synchronized (sync) {
			return createClientCertificateP12(keySize, keyPath, evpMode, country, stateOrProvince, locality, orgName, orgUnitName, commonName, csrPath,
					caKeyFile, caCrtFile, term, crtPath, name, pass, p12Path);
		}
	}
	
	public int jcreateClientCertificateCrt(int keySize,String keyPath,int evpMode,String country,String stateOrProvince,String locality,String orgName,
			String orgUnitName,String commonName,String csrPath,String caKeyFile,String caCrtFile,long term,String crtPath){
		synchronized (sync) {
			return createClientCertificateCrt(keySize, keyPath, evpMode, country, stateOrProvince, locality, orgName, orgUnitName, commonName, csrPath,
					caKeyFile, caCrtFile, term, crtPath);
		}
	}
}
