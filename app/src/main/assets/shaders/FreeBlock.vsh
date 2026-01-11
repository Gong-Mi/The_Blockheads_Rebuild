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

uniform highp mat4 mvp_matrix;
uniform highp mat4 normal_matrix;
uniform vec4 lightPosition;


varying highp vec4 outTexCoord;
varying highp vec3 outNormal;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outNormal = normalize(normal_matrix * vec4(normal.xyz, 0.0)).xyz;
    
    outLightNormal = -normalize(lightPosition.xyz / 20.0 - vec3(-0.3,0.55,0.2));
    
    outTexCoord = texCoord;
}
