package com.noodlecake.blockheads.rebuild;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

public class GameActivity extends Activity {
    static {
        try {
            android.util.Log.e("BlockheadsJava", "Loading native-lib...");
            System.loadLibrary("native-lib");
            android.util.Log.e("BlockheadsJava", "native-lib loaded successfully.");
        } catch (UnsatisfiedLinkError e) {
            android.util.Log.e("BlockheadsJava", "Failed to load native-lib: " + e.getMessage());
        }
    }

    private GameView mGameView;
    private android.view.ScaleGestureDetector mScaleDetector;

    private android.media.SoundPool mSoundPool;
    private java.util.HashMap<String, Integer> mSoundMap = new java.util.HashMap<>();

    private android.media.MediaPlayer mMusicPlayer;
    private String mCurrentMusic = "";

    private void initSoundEngine() {
        mSoundPool = new android.media.SoundPool.Builder()
                .setMaxStreams(10)
                .setAudioAttributes(new android.media.AudioAttributes.Builder()
                        .setUsage(android.media.AudioAttributes.USAGE_GAME)
                        .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build())
                .build();
        
        // Load core sound effects
        try {
            String[] sounds = {
                "dig.wav", "pickaxe.wav", "place.wav", "click.wav",
                "crunch.wav", "craftCreate.wav", "manOuch.wav", "splash.wav",
                "pop.wav", "toolBreak.wav"
            };
            for (String s : sounds) {
                android.content.res.AssetFileDescriptor afd = getAssets().openFd(s);
                mSoundMap.put(s, mSoundPool.load(afd, 1));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void playSound(String name) {
        if (!getSettingNative("sound_enabled", true)) return;
        if (mSoundMap.containsKey(name)) {
            mSoundPool.play(mSoundMap.get(name), 1.0f, 1.0f, 1, 0, 1.0f);
        }
    }

    public void playMusic(String name) {
        boolean musicEnabled = getSettingNative("music_enabled", true);
        
        if (!musicEnabled) {
             if (mMusicPlayer != null && mMusicPlayer.isPlaying()) {
                 try {
                    mMusicPlayer.stop();
                    mMusicPlayer.release();
                    mMusicPlayer = null;
                 } catch (Exception e) {}
             }
             return;
        }

        if (name.equals(mCurrentMusic) && mMusicPlayer != null && mMusicPlayer.isPlaying()) return;
        
        try {
            if (mMusicPlayer != null) {
                mMusicPlayer.stop();
                mMusicPlayer.release();
                mMusicPlayer = null;
            }

            if (name == null || name.isEmpty()) return;

            android.content.res.AssetFileDescriptor afd = getAssets().openFd(name);
            mMusicPlayer = new android.media.MediaPlayer();
            mMusicPlayer.setDataSource(afd.getFileDescriptor(), afd.getStartOffset(), afd.getLength());
            mMusicPlayer.setLooping(true);
            mMusicPlayer.setVolume(0.5f, 0.5f);
            mMusicPlayer.prepare();
            mMusicPlayer.start();
            mCurrentMusic = name;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private android.widget.ImageButton[] mHotbarSlots = new android.widget.ImageButton[10];
    private android.widget.ImageButton[] mInventorySlots = new android.widget.ImageButton[30];
    private android.widget.FrameLayout mInventoryOverlay;
    private int mSelectedInventorySlot = -1;
    private android.widget.TextView mDebugText;
    private android.widget.TextView mPlayerNameTag;
    private android.widget.LinearLayout mHealthRow;
    private android.widget.ImageView mHungerBar;

    public void updateNameTagPosition(float x, float y) {
        runOnUiThread(() -> {
            if (mPlayerNameTag == null) return;
            // Center the tag above the position
            mPlayerNameTag.setX(x - mPlayerNameTag.getWidth() / 2.0f);
            mPlayerNameTag.setY(y - mPlayerNameTag.getHeight());
        });
    }

    public void showFloatingText(float x, float y, String text, int color) {
        runOnUiThread(() -> {
            final android.widget.TextView tv = new android.widget.TextView(this);
            tv.setText(text);
            tv.setTextColor(color);
            tv.setTextSize(16);
            tv.setTypeface(null, android.graphics.Typeface.BOLD);
            tv.setShadowLayer(3, 1, 1, 0xFF000000);
            
            tv.setX(x);
            tv.setY(y);
            
            ((android.widget.FrameLayout)findViewById(android.R.id.content)).addView(tv, 
                new android.widget.FrameLayout.LayoutParams(-2, -2)); 
            
            tv.animate()
                .translationYBy(-150)
                .alpha(0.0f)
                .setDuration(2000)
                .withEndAction(() -> ((android.view.ViewGroup)tv.getParent()).removeView(tv))
                .start();
        });
    }

    public void updateStatusUI(float health, float hunger) {
        runOnUiThread(() -> {
            if (mHealthRow != null) {
                for (int i = 0; i < 5; i++) {
                    android.view.View heart = mHealthRow.getChildAt(i);
                    float threshold = (i + 1) / 5.0f;
                    if (heart != null) heart.setAlpha(health >= (threshold - 0.1f) ? 1.0f : 0.2f);
                }
            }
            if (mHungerBar != null) {
                android.widget.LinearLayout.LayoutParams lp = (android.widget.LinearLayout.LayoutParams) mHungerBar.getLayoutParams();
                lp.width = (int) (300 * hunger);
                mHungerBar.setLayoutParams(lp);
            }
        });
    }

    public void updateDebugInfo(String info) {
        runOnUiThread(() -> {
            if (mDebugText != null) {
                mDebugText.setText(info);
            }
        });
    }

    private android.graphics.Bitmap mItemsAtlas;

    public void updateHotbarSlot(int index, int type, int count) {
        if (index < 0 || index >= 30) return;
        
        runOnUiThread(() -> {
            // Update Hotbar UI (first 10 slots)
            if (index < 10 && mHotbarSlots[index] != null) {
                updateSlotImage(mHotbarSlots[index], type);
            }
            
            // Update Inventory UI (all slots)
            if (mInventorySlots[index] != null) {
                updateSlotImage(mInventorySlots[index], type);
            }
        });
    }

    private void updateSlotImage(android.widget.ImageButton slot, int type) {
        if (type == 0) {
            slot.setImageDrawable(null);
        } else {
            if (mItemsAtlas == null) {
                try {
                    mItemsAtlas = android.graphics.BitmapFactory.decodeStream(getAssets().open("Items.png"));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (mItemsAtlas != null) {
                int idx = type - 1;
                int row = idx / 32;
                int col = idx % 32;
                int size = mItemsAtlas.getWidth() / 32;
                
                try {
                    android.graphics.Bitmap icon = android.graphics.Bitmap.createBitmap(mItemsAtlas, col * size, row * size, size, size);
                    slot.setImageBitmap(icon);
                } catch (Exception e) {
                    // Fallback to color if crop fails
                    slot.setColorFilter(0xFF888888);
                }
            }
        }
    }

    private android.view.GestureDetector mGestureDetector;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initSoundEngine();
        
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        
        initNative(getExternalFilesDir(null).getAbsolutePath());

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

        // --- Basket Button (Open Inventory) ---
        android.widget.ImageButton basketBtn = new android.widget.ImageButton(this);
        try {
            android.graphics.Bitmap basketImg = android.graphics.BitmapFactory.decodeStream(getAssets().open("chestBackground.png")); // Placeholder
            basketBtn.setImageBitmap(basketImg); 
        } catch(Exception e) { basketBtn.setBackgroundColor(0xFF8B4513); }
        
        basketBtn.setOnClickListener(v -> {
            if (mInventoryOverlay != null) {
                mInventoryOverlay.setVisibility(mInventoryOverlay.getVisibility() == android.view.View.VISIBLE ? android.view.View.GONE : android.view.View.VISIBLE);
                playSound("click.wav");
                // Reset selection on close
                if (mSelectedInventorySlot != -1 && mInventorySlots[mSelectedInventorySlot] != null) {
                    mInventorySlots[mSelectedInventorySlot].clearColorFilter();
                    mSelectedInventorySlot = -1;
                }
            }
        });
        
        android.widget.FrameLayout.LayoutParams basketParams = new android.widget.FrameLayout.LayoutParams(120, 120);
        basketParams.gravity = android.view.Gravity.BOTTOM | android.view.Gravity.RIGHT;
        basketParams.rightMargin = 30; basketParams.bottomMargin = 30;
        layout.addView(basketBtn, basketParams);

        // --- Inventory Overlay ---
        mInventoryOverlay = new android.widget.FrameLayout(this);
        mInventoryOverlay.setVisibility(android.view.View.GONE);
        mInventoryOverlay.setBackgroundColor(0xCC000000); // Darker background
        mInventoryOverlay.setOnClickListener(v -> {}); // Consume clicks

        android.widget.GridLayout invGrid = new android.widget.GridLayout(this);
        invGrid.setColumnCount(6);
        invGrid.setRowCount(5);
        
        try {
            android.graphics.Bitmap slotBg = android.graphics.BitmapFactory.decodeStream(getAssets().open("InventoryButtonBackground.png"));
            android.graphics.drawable.BitmapDrawable slotDrawable = new android.graphics.drawable.BitmapDrawable(getResources(), slotBg);

            for(int i=0; i<30; i++) {
                final int slotIdx = i;
                android.widget.FrameLayout f = new android.widget.FrameLayout(this);
                android.widget.ImageButton b = new android.widget.ImageButton(this);
                b.setBackground(slotDrawable);
                b.setPadding(10,10,10,10);
                b.setScaleType(android.widget.ImageView.ScaleType.FIT_CENTER);
                mInventorySlots[i] = b;
                
                b.setOnClickListener(v -> {
                    playSound("click.wav");
                    if (mSelectedInventorySlot == -1) {
                        mSelectedInventorySlot = slotIdx;
                        b.setColorFilter(0xFF00FF00); // Highlight selected
                    } else {
                        handleSwapInventoryItemNative(mSelectedInventorySlot, slotIdx);
                        if (mInventorySlots[mSelectedInventorySlot] != null)
                             mInventorySlots[mSelectedInventorySlot].clearColorFilter();
                        mSelectedInventorySlot = -1;
                    }
                });
                
                f.addView(b, new android.widget.FrameLayout.LayoutParams(140, 140));
                
                android.widget.GridLayout.LayoutParams gp = new android.widget.GridLayout.LayoutParams();
                gp.setMargins(10, 10, 10, 10);
                invGrid.addView(f, gp);
            }
        } catch(Exception e) {}
        
        mInventoryOverlay.addView(invGrid, new android.widget.FrameLayout.LayoutParams(-2, -2, android.view.Gravity.CENTER));
        layout.addView(mInventoryOverlay);
        
        // --- 复刻左上角状态栏 (生命值 & 饥饿度) ---
        android.widget.LinearLayout statusArea = new android.widget.LinearLayout(this);
        statusArea.setOrientation(android.widget.LinearLayout.VERTICAL);
        
        try {
            android.graphics.Bitmap heartImg = android.graphics.BitmapFactory.decodeStream(getAssets().open("healthHeart.png"));
            android.graphics.Bitmap hungerBg = android.graphics.BitmapFactory.decodeStream(getAssets().open("hungerBackground.png"));
            
            // Health row
            mHealthRow = new android.widget.LinearLayout(this);
            for(int i=0; i<5; i++) {
                android.widget.ImageView heart = new android.widget.ImageView(this);
                heart.setImageBitmap(heartImg);
                mHealthRow.addView(heart, new android.widget.LinearLayout.LayoutParams(60, 60));
            }
            statusArea.addView(mHealthRow);
            
            // Hunger bar
            mHungerBar = new android.widget.ImageView(this);
            mHungerBar.setImageBitmap(hungerBg);
            mHungerBar.setScaleType(android.widget.ImageView.ScaleType.FIT_XY);
            statusArea.addView(mHungerBar, new android.widget.LinearLayout.LayoutParams(300, 40));
            
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
        
        // --- Player Name Tag ---
        mPlayerNameTag = new android.widget.TextView(this);
        mPlayerNameTag.setText("Player");
        mPlayerNameTag.setTextColor(0xFFFFFFFF);
        mPlayerNameTag.setTextSize(18);
        mPlayerNameTag.setShadowLayer(3, 2, 2, 0xFF000000);
        // Position will be updated from native code, add with default params
        layout.addView(mPlayerNameTag, new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT,
                android.widget.FrameLayout.LayoutParams.WRAP_CONTENT));

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

    private int mCurrentInteractionX, mCurrentInteractionY;

    public void openCraftingMenu(int benchId, int x, int y) {
        mCurrentInteractionX = x; mCurrentInteractionY = y;
        runOnUiThread(() -> showCraftingMenu(benchId));
    }

    public void openContainer(int x, int y) {
        mCurrentInteractionX = x; mCurrentInteractionY = y;
        runOnUiThread(() -> {
            if (mInventoryOverlay != null) {
                mInventoryOverlay.setVisibility(android.view.View.VISIBLE);
                android.widget.Toast.makeText(this, "Opened Chest at " + x + "," + y, android.widget.Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void showCraftingMenu(int benchId) {
        String jsonStr = getRecipesNative(benchId);
        
        android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(40, 40, 40, 40);
        layout.setBackgroundColor(0xEE333333);

        android.widget.TextView title = new android.widget.TextView(this);
        title.setText("CRAFTING - " + (benchId == 0 ? "HAND" : "BENCH"));
        title.setTextColor(0xFFFFFFFF);
        title.setTextSize(20);
        layout.addView(title);

        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        android.widget.LinearLayout list = new android.widget.LinearLayout(this);
        list.setOrientation(android.widget.LinearLayout.VERTICAL);

        try {
            org.json.JSONArray arr = new org.json.JSONArray(jsonStr);
            for (int i = 0; i < arr.length(); i++) {
                final org.json.JSONObject obj = arr.getJSONObject(i);
                final int recipeId = obj.getInt("id");
                
                android.widget.LinearLayout row = new android.widget.LinearLayout(this);
                row.setOrientation(android.widget.LinearLayout.HORIZONTAL);
                row.setPadding(20, 20, 20, 20);
                row.setBackgroundColor(0x33FFFFFF);
                
                // Icon
                android.widget.ImageView icon = new android.widget.ImageView(this);
                int outId = obj.getInt("outId");
                updateSlotImageDirect(icon, outId);
                row.addView(icon, new android.widget.LinearLayout.LayoutParams(120, 120));

                android.widget.LinearLayout info = new android.widget.LinearLayout(this);
                info.setOrientation(android.widget.LinearLayout.VERTICAL);
                info.setPadding(20, 0, 0, 0);

                android.widget.TextView name = new android.widget.TextView(this);
                name.setText(obj.getString("name") + " x" + obj.getInt("outCount"));
                name.setTextColor(0xFFFFFFFF);
                info.addView(name);

                android.widget.TextView cost = new android.widget.TextView(this);
                org.json.JSONArray costArr = obj.getJSONArray("cost");
                String costStr = "Cost: ";
                for(int j=0; j<costArr.length(); j++) {
                    if(j>0) costStr += ", ";
                    costStr += costArr.getJSONObject(j).getInt("n") + "x";
                }
                cost.setText(costStr);
                cost.setTextColor(0xFFAAAAAA);
                info.addView(cost);

                row.addView(info, new android.widget.LinearLayout.LayoutParams(0, -2, 1.0f));

                android.widget.Button btn = new android.widget.Button(this);
                btn.setText("CRAFT");
                btn.setOnClickListener(v -> {
                    handleCraftNative(recipeId, mCurrentInteractionX, mCurrentInteractionY);
                    playSound("click.wav");
                });
                row.addView(btn);

                android.widget.LinearLayout.LayoutParams lp = new android.widget.LinearLayout.LayoutParams(-1, -2);
                lp.setMargins(0, 10, 0, 10);
                list.addView(row, lp);
            }
        } catch (Exception e) {}

        scroll.addView(list);
        layout.addView(scroll, new android.widget.LinearLayout.LayoutParams(-1, 800));

        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(this)
            .setView(layout)
            .setNegativeButton("Close", null)
            .create();
        dialog.show();
    }

    private void updateSlotImageDirect(android.widget.ImageView view, int type) {
        if (mItemsAtlas == null) {
            try { mItemsAtlas = android.graphics.BitmapFactory.decodeStream(getAssets().open("Items.png")); } catch (Exception e) {}
        }
        if (mItemsAtlas != null && type > 0) {
            int idx = type - 1;
            int size = mItemsAtlas.getWidth() / 32;
            android.graphics.Bitmap icon = android.graphics.Bitmap.createBitmap(mItemsAtlas, (idx%32)*size, (idx/32)*size, size, size);
            view.setImageBitmap(icon);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mGameView != null) mGameView.onPause();
        saveGameNative();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (mGameView != null) mGameView.onResume();
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
    public native void handleCraftNative(int recipeId, int tx, int ty);
    public native void handleSwapInventoryItemNative(int fromSlot, int toSlot);
    public native String getRecipesNative(int benchId);
}