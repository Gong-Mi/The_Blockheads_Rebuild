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

uniform mat4 mvp_matrix;
uniform mat4 normal_matrix;
uniform vec4 worldTranslation;

varying lowp vec2 outTexCoord;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outTexCoord = texCoord.xy;
    
    highp vec4 normalMultiplied = normal_matrix * vec4(normal.xyz, 0.0);
    
    outLightNormal = normalize(worldTranslation.xyz / 40.0 + normalMultiplied.xyz);

}
