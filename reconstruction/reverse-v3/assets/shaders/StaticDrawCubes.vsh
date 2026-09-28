//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;
attribute vec4 normal;
attribute vec4 paintColor; // 1.0 - luminosity is stored in alpha

uniform mat4 mvp_matrix;
uniform vec4 lightPosition;

varying lowp vec2 outTexCoord;
varying lowp vec2 outLightTexCoord;
varying highp vec3 outLightNormal;
varying highp vec3 outNormal;
varying highp vec4 outPaintColor;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outTexCoord = texCoord.xy;
    outLightTexCoord = texCoord.zw;
    
    
    outLightNormal = normalize((positionToUse.xyz - lightPosition.xyz) / 20.0 - vec3(-0.3,0.55,0.2));
    
    outNormal = -normal.xyz;
    
    outPaintColor = paintColor;
}
