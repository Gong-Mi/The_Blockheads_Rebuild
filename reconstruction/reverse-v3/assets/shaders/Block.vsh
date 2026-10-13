//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;
attribute vec4 other;
attribute vec4 paintColor;

uniform mat4 mvp_matrix;
uniform vec4 lightPosition;

varying lowp vec3 outTexCoord;
varying lowp vec2 outLightTexCoord;
varying highp vec3 outLightNormal;
varying lowp vec4 outPaintColor;
varying highp vec2 outTexIndex;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    positionToUse.y = positionToUse.y + (texCoord.w / 255.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outTexIndex.x = position.w;
    outTexIndex.y = other.z;
    
    outTexCoord = texCoord.xyz;
    outLightTexCoord = other.xy / 256.0;
    
    outLightNormal = (lightPosition.xyz - positionToUse.xyz) / 40.0;
    
    outPaintColor = paintColor;
}
