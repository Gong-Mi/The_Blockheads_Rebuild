//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;

uniform highp mat4 mvp_matrix;

varying highp vec4 outTexCoord;

void main()
{
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    
    outTexCoord = texCoord;
}
