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

        mGameView.setOnTouchListener((v, event) -> {
            if (event.getAction() == android.view.MotionEvent.ACTION_DOWN || event.getAction() == android.view.MotionEvent.ACTION_MOVE) {
                handleMenuTouchNative(event.getX(), event.getY());
            }
            return true;
        });

        // --- Title Top-Left (Original Position) ---
        TextView title = new TextView(this);
        title.setText("THE BLOCKHEADS");
        title.setTextSize(44);
        title.setTextColor(0xFF333366); // Dark blue-purple like original
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        
        FrameLayout.LayoutParams titleParams = new FrameLayout.LayoutParams(-2, -2);
        titleParams.leftMargin = 100; titleParams.topMargin = 100;
        root.addView(title, titleParams);

        // --- Buttons Right-Side (Original Position) ---
        LinearLayout menu = new LinearLayout(this);
        menu.setOrientation(LinearLayout.VERTICAL);
        menu.setGravity(Gravity.RIGHT | Gravity.CENTER_VERTICAL);
        menu.setPadding(0, 0, 100, 0);

        try {
            android.graphics.Bitmap btnBg = android.graphics.BitmapFactory.decodeStream(getAssets().open("InventoryButtonBackground.png"));
            android.graphics.drawable.BitmapDrawable btnDrawable = new android.graphics.drawable.BitmapDrawable(getResources(), btnBg);

            String[] buttons = {"SINGLE PLAYER", "MULTIPLAYER", "OPTIONS"};
            for (String txt : buttons) {
                Button btn = new Button(this);
                btn.setText(txt);
                btn.setTextSize(22);
                btn.setTextColor(0xFFFFFFFF);
                btn.setBackground(btnDrawable); // Use original metal background
                btn.setPadding(60, 30, 60, 30);
                
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(550, -2);
                lp.setMargins(0, 15, 0, 15);
                
                btn.setOnClickListener(v -> {
                    if (txt.equals("SINGLE PLAYER")) {
                        setMenuModeNative(false);
                        startActivity(new Intent(this, GameActivity.class));
                    }
                });
                menu.addView(btn, lp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        root.addView(menu, new FrameLayout.LayoutParams(-1, -1));
        setContentView(root);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mGameView != null) mGameView.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mGameView != null) mGameView.onResume();
    }

    public void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr) {
        onSurfaceCreatedNativeInternal(assetMgr);
        setMenuModeNative(true); // Ensure menu mode is set as soon as surface is ready
    }

    public native void setMenuModeNative(boolean mode);
    public native void handleMenuTouchNative(float x, float y);
    public native void onSurfaceCreatedNativeInternal(android.content.res.AssetManager assetMgr);
    public native void onSurfaceChangedNative(int width, int height);
    public native void onDrawFrameNative();
}
