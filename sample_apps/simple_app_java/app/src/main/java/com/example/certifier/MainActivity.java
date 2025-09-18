package com.example.certifier;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import org.certifier.examples.SimpleApp;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String workDir = getFilesDir().getAbsolutePath(); // place assets here later if needed
        String result  = SimpleApp.runCertifier(workDir); // default client 127.0.0.1:8080

        TextView tv = new TextView(this);
        tv.setTextSize(16f);
        tv.setPadding(32, 64, 32, 32);
        tv.setText(result);
        setContentView(tv);
    }
}
