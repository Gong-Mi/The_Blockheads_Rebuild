//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec3 position;

uniform mat4 mvp_matrix;
uniform vec2 pointScaleAndSnowLevel;

varying highp vec3 outTexCoord;

void main()
{
    //outTexCoord.y = 1.0 - outTexCoord.y;
    outTexCoord.xy = (position.xy + vec2(1.0,0.0)) / vec2(64.0,64.0);
    
    gl_Position = mvp_matrix * vec4(position, 1.0);
    
    highp float levelOpacity = smoothstep(pointScaleAndSnowLevel.y - 16.0, pointScaleAndSnowLevel.y + 16.0, position.y);
    outTexCoord.z = levelOpacity;
    
    gl_PointSize = max((5.0 + position.z) * pointScaleAndSnowLevel.x * levelOpacity, 1.0);
    
}
