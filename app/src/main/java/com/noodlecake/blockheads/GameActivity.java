package com.noodlecake.blockheads.rebuild;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

public class GameActivity extends Activity {
    static {
        System.loadLibrary("native-lib");
    }

    private GameView mGameView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        
        android.widget.FrameLayout layout = new android.widget.FrameLayout(this);
        mGameView = new GameView(this);
        layout.addView(mGameView);

        // --- 全屏触控层 ---
        mGameView.setOnTouchListener((v, event) -> {
            if (event.getAction() == android.view.MotionEvent.ACTION_DOWN) {
                handleTouchNative(event.getX(), event.getY());
            }
            return true;
        });

        // --- 原版风格快捷栏 (还原交互) ---
        android.widget.LinearLayout hotbar = new android.widget.LinearLayout(this);
        hotbar.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        hotbar.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        
        for (int i = 0; i < 5; i++) {
            android.widget.ImageButton slot = new android.widget.ImageButton(this);
            slot.setBackgroundColor(android.graphics.Color.TRANSPARENT);
            // 以后可以在这里设置 InventoryButtonBackground.png
            slot.setImageResource(android.R.drawable.ic_menu_edit);
            final int actionId = i;
            slot.setOnClickListener(v -> handleActionNative(actionId));
            hotbar.addView(slot, new android.widget.LinearLayout.LayoutParams(120, 120));
        }

        android.widget.FrameLayout.LayoutParams hotbarParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        hotbarParams.gravity = android.view.Gravity.TOP | android.view.Gravity.CENTER_HORIZONTAL;
        hotbarParams.topMargin = 20;
        
        layout.addView(hotbar, hotbarParams);
        setContentView(layout);
        
        initNative();
    }

    public native void initNative();
    public native void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr);
    public native void onDrawFrameNative();
    public native void handleActionNative(int actionType);
    public native void handleTouchNative(float x, float y);
}
