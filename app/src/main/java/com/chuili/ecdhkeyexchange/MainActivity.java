package com.chuili.ecdhkeyexchange;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Html;
import android.util.Log;
import android.widget.TextView;

import com.chuili.ecdhkeyexchange.util.DataHelper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {

    private final String TAG = this.getClass().getName();

    private TextView publicKeyA;
    private TextView privateKeyA;
    private TextView publicKeyB;
    private TextView privateKeyB;
    private TextView sharedSecretA;
    private TextView sharedSecretB;
    private TextView plainData;
    private TextView cipheredData;
    private TextView decipheredData;
    private TextView kpGenDuration;
    private TextView sharedSecretGenDuration;
    private TextView dataEncDuration;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        publicKeyA = (TextView) findViewById(R.id.publicKeyA);
        privateKeyA = (TextView) findViewById(R.id.privateKeyA);
        publicKeyB = (TextView) findViewById(R.id.publicKeyB);
        privateKeyB = (TextView) findViewById(R.id.privateKeyB);
        sharedSecretA = (TextView) findViewById(R.id.sharedSecretA);
        sharedSecretB = (TextView) findViewById(R.id.sharedSecretB);
        plainData = (TextView) findViewById(R.id.plainData);
        cipheredData = (TextView) findViewById(R.id.encryptedData);
        decipheredData = (TextView) findViewById(R.id.decryptedData);
        kpGenDuration = (TextView) findViewById(R.id.kpGenDuration);
        sharedSecretGenDuration = (TextView) findViewById(R.id.sharedSecretGenDuration);
        dataEncDuration = (TextView) findViewById(R.id.dataEncDuration);

        secureDataExchange();
    }

    private void secureDataExchange() {
        try {
            Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());

            Log.d(TAG, "-----------[keypair generation - start]-----------");

            long beginMilis = System.currentTimeMillis();

            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "SC");
            kpg.initialize(ecParamSpec);

            // Generate key pair A
//            Log.d(TAG, "-----------[keypair A generation - start]-----------");
            KeyPair kpA = kpg.generateKeyPair();
//            Log.d(TAG, "-----------[keypair A generation - end]-----------");

            long endMilis = System.currentTimeMillis();
            long keypairGenDuration = endMilis - beginMilis;
            Log.d(TAG, "Duration for one key pair generation: " + keypairGenDuration);

            // Generate key pair B
//            Log.d(TAG, "-----------[keypair B generation - start]-----------");
            KeyPair kpB = kpg.generateKeyPair();
//            Log.d(TAG, "-----------[keypair B generation - end]-----------");
            Log.d(TAG, "-----------[keypair generation - end]-----------");

            // Generate shared secret A
            Log.d(TAG, "-----------[Shared key generation - start]-----------");
//            Log.d(TAG, "-----------[Shared key A generation - start]-----------");

            beginMilis = System.currentTimeMillis();

            KeyAgreement aKA = KeyAgreement.getInstance("ECDH", "SC");
            aKA.init(kpA.getPrivate());
            aKA.doPhase(kpA.getPublic(), true);
            SecretKey sharedKeyA = aKA.generateSecret("AES");
//            Log.d(TAG, "-----------[Shared key A generation - end]-----------");

            endMilis = System.currentTimeMillis();
            long sharedSecGenDuration = endMilis - beginMilis;
            Log.d(TAG, "Duration for shared secret generation: " + sharedSecGenDuration);

            // Generate shared secret B
//            Log.d(TAG, "-----------[Shared key B generation - start]-----------");
            KeyAgreement aKA2 = KeyAgreement.getInstance("ECDH", "SC");
            aKA2.init(kpB.getPrivate());
            aKA2.doPhase(kpB.getPublic(), true);
            SecretKey sharedKeyB = aKA2.generateSecret("AES");
//            Log.d(TAG, "-----------[Shared key B generation - end]-----------");
            Log.d(TAG, "-----------[Shared key generation - end]-----------");
            Log.d(TAG, "sharedKeyA: " + DataHelper.byteArrayToHexaStr(sharedKeyA.getEncoded()));
            Log.d(TAG, "sharedKeyB: " + DataHelper.byteArrayToHexaStr(sharedKeyB.getEncoded()));

            // Check is shared keys are same
            Log.d(TAG, "Is equal: " + DataHelper.byteArrayToHexaStr(sharedKeyA.getEncoded())
                    .equalsIgnoreCase(DataHelper.byteArrayToHexaStr(sharedKeyB.getEncoded())));

            // Encrypt data using shared key A
            String plainText = "Testing for secure data exchange";
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] iv = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                    (byte) 0x00 };

            Log.d(TAG, "-----------[Data encryption A - start]-----------");

            beginMilis = System.currentTimeMillis();

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SC");
            byte[] cipherText;

            cipher.init(Cipher.ENCRYPT_MODE, sharedKeyA, ivParameterSpec);
            cipherText = new byte[cipher.getOutputSize(plainText.length())];
            int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
            cipher.doFinal(cipherText, encryptLength);

            endMilis = System.currentTimeMillis();
            long encryptionDuration = endMilis - beginMilis;
            Log.d(TAG, "Duration for data encryption: " + encryptionDuration);
            Log.d(TAG, "-----------[Data encryption A - end]-----------");
            Log.d(TAG, "Cipher Text: " + DataHelper.byteArrayToHexaStr(cipherText));


            // Decrypt data using shared key B
//            SecretKey key = new SecretKeySpec(hexaStrToByteArray("D10FEC719D14270D1DA8489A37E1F76C147FBA2FA251F953966D86C57489FB8E"), 0, hexaStrToByteArray("D10FEC719D14270D1DA8489A37E1F76C147FBA2FA251F953966D86C57489FB8E").length, "AES");
//            byte[] cipherText = hexaStrToByteArray("4B99B501814B893C1CB20D290CA10D03629E44AB8DF2BA4D598324160F4C49C2B3D0614870D6060611D1949F8FFAF340");
//            Log.d(TAG, "-----------[Data decryption B - start]-----------");
            IvParameterSpec ivParameterSpecB = new IvParameterSpec(iv);
            Cipher cipherB = Cipher.getInstance("AES/GCM/NoPadding", "SC");
            byte[] decryptedData;

            cipherB.init(Cipher.DECRYPT_MODE, sharedKeyB, ivParameterSpecB);
            decryptedData = new byte[cipherB.getOutputSize(cipherText.length)];
            int decryptLength = cipherB.update(cipherText, 0, cipherText.length, decryptedData, 0);
            cipherB.doFinal(decryptedData, decryptLength);
//            Log.d(TAG, "-----------[Data decryption B - end]-----------");
            Log.d(TAG, "Decrypted Text: " + new String(decryptedData));

            Log.d(TAG, "Is data encrypted/decrypted correctly: " + plainText.equalsIgnoreCase(new String(decryptedData)));

            publicKeyA.setText(Html.fromHtml("<b>Public Key A: </b>"
                    + DataHelper.byteArrayToHexaStr(kpA.getPublic().getEncoded())));
            privateKeyA.setText(Html.fromHtml("<b>Private Key A: </b>"
                    + DataHelper.byteArrayToHexaStr(kpA.getPrivate().getEncoded())));
            publicKeyB.setText(Html.fromHtml("<b>Public Key B: </b>"
                    + DataHelper.byteArrayToHexaStr(kpB.getPublic().getEncoded())));
            privateKeyB.setText(Html.fromHtml("<b>Private Key B: </b>"
                    + DataHelper.byteArrayToHexaStr(kpB.getPrivate().getEncoded())));
            sharedSecretA.setText(Html.fromHtml("<b>Shared Secret A: </b>"
                    + DataHelper.byteArrayToHexaStr(sharedKeyA.getEncoded())));
            sharedSecretB.setText(Html.fromHtml("<b>Shared Secret B: </b>"
                    + DataHelper.byteArrayToHexaStr(sharedKeyB.getEncoded())));
            plainData.setText(Html.fromHtml("<b>Plain Data: </b>"
                    + plainText));
            cipheredData.setText(Html.fromHtml("<b>Encrypted Data: </b>"
                    + DataHelper.byteArrayToHexaStr(cipherText)));
            decipheredData.setText(Html.fromHtml("<b>Decrypted Data: </b>"
                    + new String(decryptedData)));
            kpGenDuration.setText(Html.fromHtml("<b>Key Pair Generation Duration (Single key pair): </b>"
                    + keypairGenDuration + "ms"));
            sharedSecretGenDuration.setText(Html.fromHtml("<b>Shared Secret Generation Duration (Single key): </b>"
                    + sharedSecGenDuration + "ms"));
            dataEncDuration.setText(Html.fromHtml("<b>Data Encryption Duration: </b>"
                    + encryptionDuration + "ms"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
