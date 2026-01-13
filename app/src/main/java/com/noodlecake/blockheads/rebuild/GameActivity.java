package com.noodlecake.blockheads.rebuild;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

public class GameActivity extends Activity {
    static {
        System.loadLibrary("native-lib");
    }

    private GameView mGameView;
    private android.view.ScaleGestureDetector mScaleDetector;

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
            String[] sounds = {"dig.wav", "pickaxe.wav", "place.wav", "click.wav"};
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
            if (mHotbarSlots[index] == null) return;
            
            // Simple mapping: 1=Dirt (brown), 2=Stone (gray)
            int color = 0x00000000;
            if (type == 1) color = 0xFF8B4513; 
            if (type == 2) color = 0xFF808080; 
            
            mHotbarSlots[index].setColorFilter(color);
        });
    }

    private android.view.GestureDetector mGestureDetector;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initSoundEngine();
        
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        
        android.widget.FrameLayout layout = new android.widget.FrameLayout(this);
        mGameView = new GameView(this);
        layout.addView(mGameView);

        mScaleDetector = new android.view.ScaleGestureDetector(this, new android.view.ScaleGestureDetector.SimpleOnScaleGestureListener() {
            @Override
            public boolean onScale(android.view.ScaleGestureDetector detector) {
                handleZoomNative(detector.getScaleFactor());
                return true;
            }
        });

        mGestureDetector = new android.view.GestureDetector(this, new android.view.GestureDetector.SimpleOnGestureListener() {
            @Override
            public boolean onSingleTapConfirmed(android.view.MotionEvent e) {
                handleTouchNative(e.getX(), e.getY());
                return true;
            }

            @Override
            public boolean onScroll(android.view.MotionEvent e1, android.view.MotionEvent e2, float distanceX, float distanceY) {
                handlePanNative(distanceX, distanceY);
                return true;
            }
        });

        mGameView.setOnTouchListener((v, event) -> {
            mScaleDetector.onTouchEvent(event);
            if (!mScaleDetector.isInProgress()) {
                mGestureDetector.onTouchEvent(event);
            }
            return true;
        });

        // --- 复刻原版底部 10 格快捷栏 ---
        android.widget.FrameLayout hotbarContainer = new android.widget.FrameLayout(this);
        android.widget.LinearLayout hotbar = new android.widget.LinearLayout(this);
        hotbar.setOrientation(android.widget.LinearLayout.HORIZONTAL);
        hotbar.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        
        try {
            android.graphics.Bitmap bgBtn = android.graphics.BitmapFactory.decodeStream(getAssets().open("InventoryButtonBackground.png"));
            android.graphics.Bitmap selBox = android.graphics.BitmapFactory.decodeStream(getAssets().open("SelectionBox40.png"));
            
            android.graphics.drawable.BitmapDrawable bgDrawable = new android.graphics.drawable.BitmapDrawable(getResources(), bgBtn);
            final android.graphics.drawable.BitmapDrawable selDrawable = new android.graphics.drawable.BitmapDrawable(getResources(), selBox);

            for (int i = 0; i < 10; i++) {
                final int slotId = i;
                android.widget.FrameLayout slotFrame = new android.widget.FrameLayout(this);
                
                android.widget.ImageButton slot = new android.widget.ImageButton(this);
                slot.setBackground(bgDrawable);
                slot.setPadding(15, 15, 15, 15);
                slot.setScaleType(android.widget.ImageView.ScaleType.FIT_CENTER);
                
                // Selection highlight overlay
                android.widget.ImageView highlight = new android.widget.ImageView(this);
                highlight.setImageDrawable(selDrawable);
                highlight.setVisibility(i == 0 ? android.view.View.VISIBLE : android.view.View.GONE);
                
                mHotbarSlots[i] = slot;
                slot.setTag(highlight); // Store reference

                slot.setOnClickListener(v -> {
                    playSound("click.wav");
                    handleActionNative(slotId);
                    // Update UI Selection
                    for(int j=0; j<10; j++) {
                        ((android.view.View)mHotbarSlots[j].getTag()).setVisibility(j == slotId ? android.view.View.VISIBLE : android.view.View.GONE);
                    }
                });

                slotFrame.addView(slot, new android.widget.FrameLayout.LayoutParams(160, 160));
                slotFrame.addView(highlight, new android.widget.FrameLayout.LayoutParams(160, 160));
                
                android.widget.LinearLayout.LayoutParams lp = new android.widget.LinearLayout.LayoutParams(150, 160);
                if (i > 0) lp.leftMargin = -15; // Overlap like original
                hotbar.addView(slotFrame, lp);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        android.widget.FrameLayout.LayoutParams hotbarParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        hotbarParams.gravity = android.view.Gravity.BOTTOM | android.view.Gravity.CENTER_HORIZONTAL;
        hotbarParams.bottomMargin = 20;
        
        layout.addView(hotbar, hotbarParams);
        
        // --- 复刻左上角状态栏 (生命值 & 饥饿度) ---
        android.widget.LinearLayout statusArea = new android.widget.LinearLayout(this);
        statusArea.setOrientation(android.widget.LinearLayout.VERTICAL);
        
        try {
            android.graphics.Bitmap heartImg = android.graphics.BitmapFactory.decodeStream(getAssets().open("healthHeart.png"));
            android.graphics.Bitmap hungerBg = android.graphics.BitmapFactory.decodeStream(getAssets().open("hungerBackground.png"));
            
            // Health row
            android.widget.LinearLayout healthRow = new android.widget.LinearLayout(this);
            for(int i=0; i<5; i++) {
                android.widget.ImageView heart = new android.widget.ImageView(this);
                heart.setImageBitmap(heartImg);
                healthRow.addView(heart, new android.widget.LinearLayout.LayoutParams(60, 60));
            }
            statusArea.addView(healthRow);
            
            // Hunger bar
            android.widget.ImageView hungerBar = new android.widget.ImageView(this);
            hungerBar.setImageBitmap(hungerBg);
            statusArea.addView(hungerBar, new android.widget.LinearLayout.LayoutParams(300, 40));
            
        } catch (Exception e) {}

        android.widget.FrameLayout.LayoutParams statusParams = new android.widget.FrameLayout.LayoutParams(600, 200);
        statusParams.leftMargin = 30; statusParams.topMargin = 30;
        layout.addView(statusArea, statusParams);

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
        craftBtn.setText("手动合成");
        craftBtn.setOnClickListener(v -> {
            showCraftingMenu(0); // Hand crafting ID = 0
        });
        
        android.widget.FrameLayout.LayoutParams craftParams = new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT);
        craftParams.gravity = android.view.Gravity.TOP | android.view.Gravity.RIGHT;
        craftParams.topMargin = 50;
        craftParams.rightMargin = 50;
        
        // --- 复刻右上角设置按钮 ---
        android.widget.ImageButton settingsBtn = new android.widget.ImageButton(this);
        try {
            android.graphics.Bitmap cogImg = android.graphics.BitmapFactory.decodeStream(getAssets().open("settingsCog.png"));
            settingsBtn.setImageBitmap(cogImg);
            settingsBtn.setBackground(null);
            settingsBtn.setPadding(20, 20, 20, 20);
            settingsBtn.setScaleType(android.widget.ImageView.ScaleType.FIT_CENTER);
        } catch (Exception e) {}

        settingsBtn.setOnClickListener(v -> showSettingsDialog());

        android.widget.FrameLayout.LayoutParams settingsParams = new android.widget.FrameLayout.LayoutParams(140, 140);
        settingsParams.gravity = android.view.Gravity.TOP | android.view.Gravity.RIGHT;
        settingsParams.topMargin = 20; settingsParams.rightMargin = 20;
        layout.addView(settingsBtn, settingsParams);

        setContentView(layout);
        initNative(getExternalFilesDir(null).getAbsolutePath());
    }

    private android.widget.FrameLayout mSettingsOverlay;

    public native void setSettingNative(String key, boolean value);
    public native boolean getSettingNative(String key, boolean defaultValue);

    private void showSettingsDialog() {
        if (mSettingsOverlay != null) {
            mSettingsOverlay.setVisibility(android.view.View.VISIBLE);
            return;
        }
        // ... (rest of initialization)

        mSettingsOverlay = new android.widget.FrameLayout(this);
        mSettingsOverlay.setBackgroundColor(0x88000000); // Dim background
        mSettingsOverlay.setOnClickListener(v -> mSettingsOverlay.setVisibility(android.view.View.GONE));

        try {
            // --- Settings Window ---
            android.widget.LinearLayout window = new android.widget.LinearLayout(this);
            window.setOrientation(android.widget.LinearLayout.VERTICAL);
            window.setPadding(60, 60, 60, 60);
            window.setGravity(android.view.Gravity.CENTER);
            
            android.graphics.Bitmap bg = android.graphics.BitmapFactory.decodeStream(getAssets().open("pauseBackground.png"));
            window.setBackground(new android.graphics.drawable.BitmapDrawable(getResources(), bg));

            // --- Title ---
            android.widget.TextView title = new android.widget.TextView(this);
            title.setText("SETTINGS");
            title.setTextSize(32);
            title.setTextColor(0xFFFFFFFF);
            title.setGravity(android.view.Gravity.CENTER);
            window.addView(title);

            // --- Scrollable Settings Area ---
            android.widget.ScrollView scrollView = new android.widget.ScrollView(this);
            android.widget.LinearLayout list = new android.widget.LinearLayout(this);
            list.setOrientation(android.widget.LinearLayout.VERTICAL);
            
            String[] options = {"MUSIC", "SOUND FX", "HD TEXTURES", "BETTER SKY", "PVP MODE", "CLOUDS", "LEFT HANDED"};
            final String[] keys = {"music_enabled", "sound_enabled", "hd_textures", "better_sky", "pvp_enabled", "clouds_enabled", "left_handed"};
            
            for (int i=0; i<options.length; i++) {
                final int idx = i;
                android.widget.LinearLayout row = new android.widget.LinearLayout(this);
                row.setOrientation(android.widget.LinearLayout.HORIZONTAL);
                row.setGravity(android.view.Gravity.CENTER_VERTICAL);
                row.setPadding(0, 20, 0, 20);

                android.widget.TextView label = new android.widget.TextView(this);
                label.setText(options[i]);
                label.setTextColor(0xFFFFFFFF);
                label.setTextSize(18);
                row.addView(label, new android.widget.LinearLayout.LayoutParams(0, -2, 1.0f));

                final android.widget.ImageView toggle = new android.widget.ImageView(this);
                final android.graphics.Bitmap onBmp = android.graphics.BitmapFactory.decodeStream(getAssets().open("toggleButtonOn.png"));
                final android.graphics.Bitmap offBmp = android.graphics.BitmapFactory.decodeStream(getAssets().open("toggleButtonOff.png"));
                
                boolean startVal = getSettingNative(keys[idx], i < 4); // Default some to true
                toggle.setImageBitmap(startVal ? onBmp : offBmp); 
                toggle.setTag(startVal);
                
                toggle.setOnClickListener(v -> {
                    boolean newVal = !((boolean)toggle.getTag());
                    toggle.setTag(newVal);
                    toggle.setImageBitmap(newVal ? onBmp : offBmp);
                    setSettingNative(keys[idx], newVal);
                    playSound("click.wav");
                });
                
                row.addView(toggle, new android.widget.LinearLayout.LayoutParams(100, 50));
                list.addView(row);
            }
            scrollView.addView(list);
            window.addView(scrollView, new android.widget.LinearLayout.LayoutParams(-1, 600));

            // --- Close Button ---
            android.widget.ImageButton closeBtn = new android.widget.ImageButton(this);
            android.graphics.Bitmap closeImg = android.graphics.BitmapFactory.decodeStream(getAssets().open("closeX.png"));
            closeBtn.setImageBitmap(closeImg);
            closeBtn.setBackground(null);
            closeBtn.setOnClickListener(v -> mSettingsOverlay.setVisibility(android.view.View.GONE));
            
            android.widget.FrameLayout.LayoutParams closeParams = new android.widget.FrameLayout.LayoutParams(80, 80);
            closeParams.gravity = android.view.Gravity.TOP | android.view.Gravity.RIGHT;
            
            android.widget.FrameLayout container = new android.widget.FrameLayout(this);
            container.addView(window, new android.widget.FrameLayout.LayoutParams(800, -2, android.view.Gravity.CENTER));
            container.addView(closeBtn, closeParams);

            mSettingsOverlay.addView(container);
            
            ((android.widget.FrameLayout)findViewById(android.R.id.content)).addView(mSettingsOverlay);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void openCraftingMenu(int benchId) {
        runOnUiThread(() -> showCraftingMenu(benchId));
    }

    private void showCraftingMenu(int benchId) {
        String jsonStr = getRecipesNative(benchId);
        
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(this);
        String title = "Crafting";
        if (benchId == 0) title = "Hand Crafting";
        if (benchId == 10) title = "Workbench";
        if (benchId == 11) title = "Tool Bench";
        
        builder.setTitle(title);

        final java.util.ArrayList<String> names = new java.util.ArrayList<>();
        final java.util.ArrayList<Integer> ids = new java.util.ArrayList<>();

        try {
            org.json.JSONArray arr = new org.json.JSONArray(jsonStr);
            if (arr.length() == 0) {
                names.add("No recipes available.");
            } else {
                for (int i = 0; i < arr.length(); i++) {
                    org.json.JSONObject obj = arr.getJSONObject(i);
                    int id = obj.getInt("id");
                    String name = obj.getString("name");
                    int outCount = obj.getInt("outCount");
                    
                    String label = name + " x" + outCount;
                    
                    org.json.JSONArray cost = obj.getJSONArray("cost");
                    label += " (";
                    for(int j=0; j<cost.length(); j++) {
                        org.json.JSONObject c = cost.getJSONObject(j);
                        if(j>0) label += ", ";
                        label += c.getInt("n") + " x ID:" + c.getInt("id");
                    }
                    label += ")";

                    names.add(label);
                    ids.add(id);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            names.add("Error parsing recipes");
        }

        builder.setItems(names.toArray(new String[0]), (dialog, which) -> {
            if (which < ids.size()) {
                int recipeId = ids.get(which);
                handleCraftNative(recipeId);
            }
        });
        
        builder.setNegativeButton("Close", null);
        builder.show();
    }

    @Override
    protected void onPause() {
        super.onPause();
        saveGameNative();
    }

    public native void initNative(String storageDir);
    public native void saveGameNative();
    public native void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr);
    public native void onSurfaceChangedNative(int width, int height);
    public native void onDrawFrameNative();
    public native void handleActionNative(int actionType);
    public native void handleTouchNative(float x, float y);
    public native void handlePanNative(float dx, float dy);
    public native void handleZoomNative(float scaleFactor);
    public native void handleCraftNative(int recipeId);
    public native String getRecipesNative(int benchId);
}
