package com.noodlecake.blockheads.rebuild;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.content.res.AssetManager;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

public class GameView extends GLSurfaceView {
    private final Renderer renderer;

    public GameView(Context context) {
        super(context);
        setEGLContextClientVersion(2); // 使用 OpenGL ES 2.0
        
        final AssetManager assetManager = context.getAssets();
        
        renderer = new Renderer() {
            @Override
            public void onSurfaceCreated(GL10 gl, EGLConfig config) {
                if (context instanceof GameActivity)
                    ((GameActivity)context).onSurfaceCreatedNative(assetManager);
                else if (context instanceof MainMenuActivity)
                    ((MainMenuActivity)context).onSurfaceCreatedNative(assetManager);
            }

            @Override
            public void onSurfaceChanged(GL10 gl, int width, int height) {
                if (context instanceof GameActivity)
                    ((GameActivity)context).onSurfaceChangedNative(width, height);
                else if (context instanceof MainMenuActivity)
                    ((MainMenuActivity)context).onSurfaceChangedNative(width, height);
            }

            @Override
            public void onDrawFrame(GL10 gl) {
                if (context instanceof GameActivity)
                    ((GameActivity)context).onDrawFrameNative();
                else if (context instanceof MainMenuActivity)
                    ((MainMenuActivity)context).onDrawFrameNative();
            }
        };
        
        setRenderer(renderer);
    }
}
