package com.sgc.nativetest;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.sgc.nativetest.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'nativetest' library on application startup.
    static {
        System.loadLibrary("nativetest");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        Button btn1 = findViewById(R.id.btn1);
        btn1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                TextView t = findViewById(R.id.flag_field);
                String flag = t.getText().toString();
                if (flag.isEmpty()){
                    Toast error = Toast.makeText(getApplicationContext(), "Flag field is empty", Toast.LENGTH_LONG);
                    error.show();
                    return;
                }

                Toast result;
                String msg = verifyFlag(flag) ? "CORRECT FLAG!!! YOU MADE IT ;)" : "Incorrect flag, please try again...";
                result = Toast.makeText(getApplicationContext(), msg, Toast.LENGTH_LONG);
                result.show();
            }
        });

    }

    /**
     * A native method that is implemented by the 'nativetest' native library,
     * which is packaged with this application.
     */
    public native boolean verifyFlag(String flag);
}