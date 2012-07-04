package org.nick.keystoretest;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.util.Log;

public class KeystoreReceiver extends BroadcastReceiver {

    private static final String TAG = KeystoreReceiver.class.getSimpleName();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals(KeyChain.ACTION_STORAGE_CHANGED)) {
            Log.d(TAG, "Key store changed");
            Bundle extras = intent.getExtras();
            if (extras != null) {
                Log.d(TAG, "extras: " + extras.keySet());
            } else {
                Log.d(TAG, "No extras");
            }
        }
    }

}
