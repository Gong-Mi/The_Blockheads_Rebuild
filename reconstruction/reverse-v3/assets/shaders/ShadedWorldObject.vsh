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

varying highp vec4 outTexCoord;
varying highp float lighting;

void main()
{
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    
    highp vec4 outNormal = normal_matrix * vec4(normal.xyz, 0.0);
    
    lighting = max((dot(outNormal.xyz, normalize(vec3(0.0,1.0,0.8))) + 0.4), 0.2);
    
    outTexCoord = texCoord;
}
