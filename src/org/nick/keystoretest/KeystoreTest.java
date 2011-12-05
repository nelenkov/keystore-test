package org.nick.keystoretest;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.Toast;

public class KeystoreTest extends Activity implements OnClickListener,
        KeyChainAliasCallback {

    private static final String TAG = KeystoreTest.class.getSimpleName();

    private static final String PKCS12_FILENAME = "keystore-test.pfx";
    private static final String CA_CERT_FILENAME = "cacert.pem";

    private Button installPkcs12Button;
    private Button installCertButton;
    private Button useKeyButton;
    private Button listTrustedCertsButton;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        setContentView(R.layout.main);

        setProgressBarIndeterminateVisibility(false);

        installPkcs12Button = (Button) findViewById(R.id.install_pkcs12_button);
        installPkcs12Button.setOnClickListener(this);

        useKeyButton = (Button) findViewById(R.id.use_key_button);
        useKeyButton.setOnClickListener(this);

        installCertButton = (Button) findViewById(R.id.install_cert_button);
        installCertButton.setOnClickListener(this);

        listTrustedCertsButton = (Button) findViewById(R.id.list_trusted_certs);
        listTrustedCertsButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        try {
            if (v.getId() == R.id.install_pkcs12_button) {
                Intent intent = KeyChain.createInstallIntent();
                byte[] p12 = readFile(PKCS12_FILENAME);
                intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
                startActivity(intent);
            } else if (v.getId() == R.id.install_cert_button) {
                Intent intent = KeyChain.createInstallIntent();
                Log.d(TAG, "Intent: " + intent.getComponent().toString());
                byte[] cert = readFile(CA_CERT_FILENAME);
                intent.putExtra(KeyChain.EXTRA_CERTIFICATE, cert);
                startActivity(intent);
            } else if (v.getId() == R.id.use_key_button) {
                KeyChain.choosePrivateKeyAlias(this, this,
                        new String[] { "RSA" }, null, null, -1, null);
            } else if (v.getId() == R.id.list_trusted_certs) {
                final Context ctx = this;
                new AsyncTask<Void, Void, Boolean>() {

                    private Exception error;
                    private int numSystemCerts;
                    private int numUserCerts;

                    @Override
                    protected void onPreExecute() {
                        Toast.makeText(
                                ctx,
                                "Listing trusted certificates, check logcat...",
                                Toast.LENGTH_LONG).show();
                        setProgressBarIndeterminateVisibility(true);
                    }

                    @Override
                    protected Boolean doInBackground(Void... arg) {
                        try {
                            //                            listCertAliasesReflection();

                            KeyStore ks = KeyStore
                                    .getInstance("AndroidCAStore");
                            ks.load(null, null);

                            Enumeration<String> aliases = ks.aliases();
                            while (aliases.hasMoreElements()) {
                                String alias = aliases.nextElement();
                                if (alias.startsWith("user:")) {
                                    numUserCerts++;
                                } else {
                                    numSystemCerts++;
                                }
                                X509Certificate cert = (X509Certificate) ks
                                        .getCertificate(alias);
                                Log.d(TAG, alias + "-> DN: "
                                        + cert.getSubjectDN().getName());
                            }

                            return true;
                        } catch (Exception e) {
                            Log.e(TAG, "Error listing trusted certs", e);
                            error = e;

                            return false;
                        }
                    }

                    protected void onPostExecute(Boolean trusted) {
                        setProgressBarIndeterminateVisibility(false);

                        if (error != null) {
                            Toast.makeText(ctx, "Error: " + error.getMessage(),
                                    Toast.LENGTH_LONG).show();

                            return;
                        }

                        String message = String.format(
                                "Found %d system and %d user trusted certs",
                                numSystemCerts, numUserCerts);
                        Toast.makeText(ctx, message, Toast.LENGTH_SHORT).show();
                    }
                }.execute();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error validating certificate", e);
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private byte[] readFile(String filename) throws Exception {
        File f = new File(Environment.getExternalStorageDirectory(), filename);
        byte[] result = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        in.read(result);
        in.close();

        return result;
    }

    @Override
    public void alias(final String alias) {
        Log.d(TAG, "Thread: " + Thread.currentThread().getName());
        Log.d(TAG, "selected alias: " + alias);

        final Context ctx = KeystoreTest.this;
        Runnable r = new Runnable() {
            public void run() {
                try {
                    Toast.makeText(ctx, "Found key: " + alias,
                            Toast.LENGTH_SHORT).show();

                    new AsyncTask<Void, Void, Boolean[]>() {

                        private Exception error;

                        @Override
                        protected void onPreExecute() {
                            Toast.makeText(
                                    ctx,
                                    "Signing data and validating user certificate, check logcat...",
                                    Toast.LENGTH_LONG).show();
                            setProgressBarIndeterminateVisibility(true);
                        }

                        @Override
                        protected Boolean[] doInBackground(Void... arg0) {
                            try {
                                PrivateKey pk = KeyChain.getPrivateKey(ctx,
                                        alias);
                                X509Certificate[] chain = KeyChain
                                        .getCertificateChain(ctx, alias);
                                Log.d(TAG, "chain length: " + chain.length);
                                for (X509Certificate cert : chain) {
                                    Log.d(TAG, "Subject DN: "
                                            + cert.getSubjectDN().getName());
                                    Log.d(TAG, "Issuer DN: "
                                            + cert.getIssuerDN().getName());
                                }

                                Boolean[] result = new Boolean[2];
                                byte[] data = "foobar".getBytes("ASCII");
                                Signature sig = Signature
                                        .getInstance("SHA1withRSA");
                                sig.initSign(pk);
                                sig.update(data);
                                byte[] signed = sig.sign();

                                PublicKey pubk = chain[0].getPublicKey();
                                sig.initVerify(pubk);
                                sig.update(data);
                                boolean valid = sig.verify(signed);
                                Log.d(TAG, "signature is valid: " + valid);
                                result[0] = valid;

                                TrustManagerFactory tmf = TrustManagerFactory
                                        .getInstance("X509");
                                Log.d(TAG, "TrustManagerFactory provider "
                                        + tmf.getProvider().getName());
                                tmf.init((KeyStore) null);
                                TrustManager[] tms = tmf.getTrustManagers();
                                Log.d(TAG, "num trust managers: " + tms.length);

                                X509TrustManager xtm = (X509TrustManager) tms[0];
                                Log.d(TAG, "checking chain with " + xtm);
                                try {
                                    xtm.checkClientTrusted(chain, "RSA");
                                    Log.d(TAG, "chain is valid");
                                    result[1] = true;
                                } catch (CertificateException ce) {
                                    Log.e(TAG,
                                            "Error validating certificate chain.",
                                            ce);
                                    result[1] = false;
                                }

                                return result;
                            } catch (Exception e) {
                                Log.e(TAG, "Error using private key", e);
                                error = e;

                                return null;
                            }
                        }

                        protected void onPostExecute(Boolean[] valid) {
                            setProgressBarIndeterminateVisibility(false);

                            if (valid == null && error != null) {
                                Toast.makeText(ctx,
                                        "Error: " + error.getMessage(),
                                        Toast.LENGTH_LONG).show();

                                return;
                            }

                            boolean signatureValid = valid[0];
                            boolean certTrusted = valid[1];

                            String message = String
                                    .format("Signature valid: %s, cert chain trusted: %s",
                                            signatureValid, certTrusted);
                            Toast.makeText(ctx, message, Toast.LENGTH_SHORT)
                                    .show();
                        }
                    }.execute();
                } catch (Exception e) {
                    Log.e(TAG, "Error getting private key.", e);
                    Toast.makeText(ctx, e.getMessage(), Toast.LENGTH_LONG)
                            .show();
                }
            }
        };
        runOnUiThread(r);
    }

    @SuppressWarnings("unchecked")
    private void listCertAliasesReflection() throws Exception {
        Class<?> cl = Class
                .forName("org.apache.harmony.xnet.provider.jsse.TrustedCertificateStore");
        Method m = cl.getMethod("aliases", (Class<?>[]) null);
        Object ts = cl.newInstance();
        Set<String> alaises = (Set<String>) m.invoke(ts, (Object[]) null);
        Log.d(TAG, "aliases: " + alaises);
    }
}
