//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 shades;
attribute vec2 shadeCoords;
//attribute vec4 color;

uniform mat4 mvp_matrix;

varying highp vec4 outShades;
varying highp vec2 outShadeCoords;
//varying highp vec4 outColor;

void main()
{
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    
    outShadeCoords = shadeCoords;
    outShades = shades / 256.0;
}
