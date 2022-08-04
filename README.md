
# CRYSTALS KYBER Java

<p align="center">
  <img src="./kyber.png"/>
</p>

**KYBER** is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices.  The homepage for CRYSTALS Kyber can be found [here](https://pq-crystals.org/kyber/index.shtml) (some information from this README is pulled directly from their site).

The initial Java implementation was intended for Android applications. In order to use it on Android however, you need to include the sun.security.util classes in your final jar.  The Android version of java does not have them available.

Some minor changes were needed for this library to work with JDK 18 (version 2.0+).  In order to use the library in your Java 18 app, you do need modifications to your maven pom (sorry.. no gradle example).

*Please note, do not add the "..." to your pom file.  That's just a placeholder instead of adding a full pom file.*

```bash
<project ...>
....
   <properties>
     <!-- This property must be added -->
     <argLine>--add-modules java.base --add-opens java.base/sun.security.util=ALL-UNNAMED</argLine>
     ...
   </properties>
   <build>
     <plugins>
       <plugin>
         <groupId>org.apache.maven.plugins</groupId>
         <artifactId>maven-compiler-plugin</artifactId>
         <version>3.10.1</version>
         <configuration>
           <source>18</source>
           <target>18</target>
           <!-- This section must be added -->
           <compilerArgs>
             <arg>--add-exports</arg>
             <arg>java.base/sun.security.util=ALL-UNNAMED</arg>
           </compilerArgs>
         </configuration>
       </plugin>
...
</project>
```

The "builds" directory contains a compiled OpenJDK 13.0.2 version (kyberJCE-0.0.1-JDK13.jar) of this library and a signed Oracle JDK 18 version (kyberJCE-2.1.1.jar).  Both jar files have an md5 hash file for verification.

The initial creation of this code was translated from this Go implementation of [Kyber (version 3)](https://github.com/symbolicsoft/kyber-k2so).  After getting that to work, the code was modified into a JCE (unsigned).  The Diffie-Hellman OpenJDK 11 code was used as a base.

Kyber has three different parameter sets: 512, 768, and 1024.  Kyber-512 aims at security roughly equivalent to AES-128, Kyber-768 aims at security roughly equivalent to AES-192, and Kyber-1024 aims at security roughly equivalent to AES-256. 

## Loading the Kyber JCE
There are a couple ways to load the Kyber JCE.  One way is to add these two lines to your program:

```bash
Security.setProperty("crypto.policy", "unlimited");
Security.addProvider(new KyberJCE());
```

## Example Use 
The following code will show a basic Key Agreement between two parties.  (Additional AES encryption is recommended for further securing remote communication.)

```bash
// Alice generates a KeyPair and sends her public key to Bob
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
KeyPair aliceKeyPair = keyGen.generateKeyPair();
```

```bash
// Bob Generates a KeyPair and an initial Key Agreement
// "Kyber512" or "Kyber768" or "Kyber1024" are options for Key Generation
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber1024");
KeyPair bobKeyPair = keyGen.generateKeyPair();
KeyAgreement keyAgreement = KeyAgreement.getInstance("Kyber");
keyAgreement.init(bobKeyPair.getPrivate());
```

```bash
// Bob generates a Secret Key and Cipher Text from Alice's Public Key
// KyberEncrypted holds the Secret Key and the Cipher Text
KyberEncrypted kyberEncrypted = (KyberEncrypted) keyAgreement.doPhase((KyberPublicKey) alicePublicKey, true);
```

```bash
// Bob sends Alice the generated Cipher Text 
// Alice creates her own KeyAgreement and initializes it with her private key
KeyAgreement keyAgreement = KeyAgreement.getInstance("Kyber");
keyAgreement.init((KyberPrivateKey) alicePrivateKey);
```

```bash
// Alice generates the same Secret Key from the Cipher Text
// KyberDecrypted holds the Secret Key (will be the same one that Bob generated) and the variant
KyberDecrypted kyberDecrypted = (KyberDecrypted) keyAgreement.doPhase(cipherText, true);
```
   
## DISCLAIMER
This library is available under the MIT License. The tests from the [Go](https://github.com/symbolicsoft/kyber-k2so) implementation have been converted to Java.  The original test files are used as the main test source.  Additional tests include X.509 encoding and decoding, a key agreement, and a massively multi-threaded key agreement test for good measure. The tests all pass, however please note that the code has not been examined by a third party for potential vulnerabilities.

## Further Information
More details about CRYSTALS and the most secure ways to use it can be found [here](https://pq-crystals.org/index.shtml)

## Contact
swiftcryptollc@gmail.com
