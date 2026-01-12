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
        
        // 使用相对布局，方便叠加按钮
        android.widget.RelativeLayout layout = new android.widget.RelativeLayout(this);
        mGameView = new GameView(this);
        layout.addView(mGameView);

        // 添加一个测试按钮 (对应原版的挖掘模式)
        android.widget.Button mineBtn = new android.widget.Button(this);
        mineBtn.setText("挖掘模式");
        android.widget.RelativeLayout.LayoutParams params = new android.widget.RelativeLayout.LayoutParams(
                200, 150);
        params.addRule(android.widget.RelativeLayout.ALIGN_PARENT_TOP);
        params.addRule(android.widget.RelativeLayout.ALIGN_PARENT_RIGHT);
        mineBtn.setLayoutParams(params);
        mineBtn.setOnClickListener(v -> handleActionNative(0)); // 0 为挖掘
        
        layout.addView(mineBtn);
        setContentView(layout);
        
        initNative();
    }

    public native void initNative();
    public native void onSurfaceCreatedNative(android.content.res.AssetManager assetMgr);
    public native void onDrawFrameNative();
    public native void handleActionNative(int actionType);
    public native void handleTouchNative(float x, float y);
}
