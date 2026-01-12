package com.noodlecake.blockheads.rebuild;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

public class GameActivity extends Activity {
    static {
        System.loadLibrary("native-lib");
    }

    private GameView mGameView;

    private android.media.SoundPool mSoundPool;
    private java.util.HashMap<String, Integer> mSoundMap = new java.util.HashMap<>();

    private void initSoundEngine() {
        mSoundPool = new android.media.SoundPool.Builder()
                .setMaxStreams(10)
                .setAudioAttributes(new android.media.AudioAttributes.Builder()
                        .setUsage(android.media.AudioAttributes.USAGE_GAME)
                        .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build())
                .build();
        
        // 预加载几个核心音效 (还原自 assets)
        try {
            String[] sounds = {"dig.wav", "pickaxe.wav", "place.wav"};
            for (String s : sounds) {
                android.content.res.AssetFileDescriptor afd = getAssets().openFd(s);
                mSoundMap.put(s, mSoundPool.load(afd, 1));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void playSound(String name) {
        if (mSoundMap.containsKey(name)) {
            mSoundPool.play(mSoundMap.get(name), 1.0f, 1.0f, 1, 0, 1.0f);
        }
    }

    private android.widget.ImageButton[] mHotbarSlots = new android.widget.ImageButton[10];
    private android.widget.TextView mDebugText;

    public void updateDebugInfo(String info) {
        runOnUiThread(() -> {
            if (mDebugText != null) {
                mDebugText.setText(info);
            }
        });
    }

    public void updateHotbarSlot(int index, int type, int count) {
        if (index < 0 || index >= 10) return;
        
        runOnUiThread(() -> {
            // Simple mapping: 1=Dirt (brown), 2=Stone (gray)
            // Real implementation needs texture regions
            int color = 0x00000000;
            if (type == 1) color = 0xFF8B4513; // Brown
            if (type == 2) color = 0xFF808080; // Gray
            
            mHotbarSlots[index].setColorFilter(color);
            // Ideally set text for count, but ImageButton doesn't support text directly
            // Just color feedback for now to prove it works
        });
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initSoundEngine();
        
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        
        android.widget.FrameLayout layout = new android.widget.FrameLayout(this);
        mGameView = new GameView(this);
        layout.addView(mGameView);

        // --- 全屏触控层 ---
        mGameView.setOnTouchListener(new android.view.View.OnTouchListener() {
            private float lastX, lastY;
            
            @Override
            public boolean onTouch(android.view.View v, android.view.MotionEvent event) {
                float x = event.getX();
                float y = event.getY();
                
                switch (event.getAction()) {
                    case android.view.MotionEvent.ACTION_DOWN:
                        lastX = x;
                        lastY = y;
                        handleTouchNative(x, y); // AI Walk/Interaction
                        break;
                    case android.view.MotionEvent.ACTION_MOVE:
                        float dx = x - lastX;
                        float dy = y - lastY;
                        handlePanNative(dx, dy);
                        lastX = x;
                        lastY = y;
                        break;
                }
                return true;
            }
        });

        // --- 还原原版底部 10 格快捷栏 ---
        android.widget.LinearLayout hotbar = new android.widget.LinearLayout(this);
        hotbar.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        hotbar.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        
        try {
            android.graphics.Bitmap bgBtn = android.graphics.BitmapFactory.decodeStream(getAssets().open("InventoryButtonBackground.png"));
            android.graphics.drawable.BitmapDrawable drawable = new android.graphics.drawable.BitmapDrawable(getResources(), bgBtn);

            for (int i = 0; i < 10; i++) {
                android.widget.ImageButton slot = new android.widget.ImageButton(this);
                slot.setBackground(drawable);
                slot.setPadding(10, 10, 10, 10);
                slot.setScaleType(android.widget.ImageView.ScaleType.CENTER_INSIDE);
                
                mHotbarSlots[i] = slot;

                final int slotId = i;
                slot.setOnClickListener(v -> {
                    playSound("click.wav");
                    handleActionNative(slotId);
                });
                hotbar.addView(slot, new android.widget.LinearLayout.LayoutParams(140, 140));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        android.widget.FrameLayout.LayoutParams hotbarParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        hotbarParams.gravity = android.view.Gravity.BOTTOM | android.view.Gravity.CENTER_HORIZONTAL;
        hotbarParams.bottomMargin = 30;
        
        layout.addView(hotbar, hotbarParams);
        
        // --- Debug Info Overlay ---
        mDebugText = new android.widget.TextView(this);
        mDebugText.setTextColor(0xFFFFFFFF);
        mDebugText.setTextSize(16);
        mDebugText.setText("Initializing...");
        mDebugText.setShadowLayer(2, 1, 1, 0xFF000000);
        android.widget.FrameLayout.LayoutParams debugParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        debugParams.gravity = android.view.Gravity.TOP | android.view.Gravity.LEFT;
        debugParams.topMargin = 20;
        debugParams.leftMargin = 20;
        layout.addView(mDebugText, debugParams);
        
        // --- 合成引擎联动测试 ---
        android.widget.Button craftBtn = new android.widget.Button(this);
        craftBtn.setText("一键合成工具");
        craftBtn.setOnClickListener(v -> {
            v.performHapticFeedback(android.view.HapticFeedbackConstants.VIRTUAL_KEY);
            handleCraftNative(50); // 请求合成石镐
            handleCraftNative(20); // 请求合成火把
        });
        
        android.widget.FrameLayout.LayoutParams craftParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        craftParams.gravity = android.view.Gravity.TOP | android.view.Gravity.RIGHT;
        craftParams.topMargin = 50;
        craftParams.rightMargin = 50;
        
        layout.addView(craftBtn, craftParams);
        setContentView(layout);
        
        initNative();
    }

    public native void initNative();
    public native void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr);
    public native void onSurfaceChangedNative(int width, int height);
    public native void onDrawFrameNative();
    public native void handleActionNative(int actionType);
    public native void handleTouchNative(float x, float y);
    public native void handlePanNative(float dx, float dy);
    public native void handleCraftNative(int targetItemId);
}
