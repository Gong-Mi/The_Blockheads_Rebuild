//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;
attribute vec4 texCoordB;

uniform mat4 mvp_matrix;
uniform vec4 lightPosition;

varying lowp vec2 outTexCoord;
varying lowp vec2 outTexCoordB;
varying lowp vec2 outLightTexCoord;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outTexCoord = texCoord.xy;
    outLightTexCoord = texCoord.zw;
    outTexCoordB = texCoordB.xy;
    
    outLightNormal = normalize((positionToUse.xyz - lightPosition.xyz) / 20.0 - vec3(-0.2,0.4,1.0));
}
