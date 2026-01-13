package com.noodlecake.blockheads.rebuild;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainMenuActivity extends Activity {
    static {
        System.loadLibrary("native-lib");
    }

    private GameView mGameView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF87CEEB); 

        // --- Add GL View for Giant Character ---
        mGameView = new GameView(this);
        root.addView(mGameView);

        LinearLayout menu = new LinearLayout(this);
        menu.setOrientation(LinearLayout.VERTICAL);
        menu.setGravity(Gravity.CENTER);
        
        // ... rest of menu logic ...

        // --- Title Placeholder ---
        TextView title = new TextView(this);
        title.setText("THE BLOCKHEADS");
        title.setTextSize(48);
        title.setTextColor(0xFF222244);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 100);
        menu.addView(title);

        String[] buttons = {"SINGLE PLAYER", "MULTIPLAYER", "OPTIONS"};
        for (String txt : buttons) {
            Button btn = new Button(this);
            btn.setText(txt);
            btn.setTextSize(24);
            btn.setBackgroundColor(0xAAFFFFFF);
            btn.setPadding(40, 20, 40, 20);
            
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(600, -2);
            lp.setMargins(0, 20, 0, 20);
            
            btn.setOnClickListener(v -> {
                if (txt.equals("SINGLE PLAYER")) {
                    setMenuModeNative(false);
                    startActivity(new Intent(this, GameActivity.class));
                }
            });
            menu.addView(btn, lp);
        }

        root.addView(menu);
        setContentView(root);
        
        // Wait for surface and set mode
        new android.os.Handler().postDelayed(() -> setMenuModeNative(true), 500);
    }

    public native void setMenuModeNative(boolean mode);
    public native void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr);
    public native void onSurfaceChangedNative(int width, int height);
    public native void onDrawFrameNative();
}
