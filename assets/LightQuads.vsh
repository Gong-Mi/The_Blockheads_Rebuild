//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;
attribute vec4 paintColor; // 1.0 - luminosity is stored in alpha

uniform mat4 mvp_matrix;

varying lowp vec3 outTexCoord;
varying lowp vec4 outPaintColor;

void main()
{
    highp vec4 positionToUse = vec4(position.xyz,1.0);
    gl_Position = mvp_matrix * positionToUse;
    
    outTexCoord = texCoord.xyz;
    outPaintColor = paintColor;
}
