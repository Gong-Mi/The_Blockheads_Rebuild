//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec3 position;

uniform mat4 mvp_matrix;
uniform float snowLevel;

varying highp vec3 outTexCoord;

void main()
{
    outTexCoord.xy = (position.xy + vec2(1.0,0.0)) / vec2(64.0,64.0);
    
    highp float levelOpacity = smoothstep(snowLevel + 16.0, snowLevel - 16.0, position.y);
    outTexCoord.z = levelOpacity;
    
    gl_Position = mvp_matrix * vec4(position, 1.0);
    
}
