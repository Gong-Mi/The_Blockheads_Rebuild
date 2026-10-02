//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;
attribute vec4 texCoord;
attribute vec4 cloud;

uniform mat4 mvp_matrix;

varying highp vec4 outTexCoord;
varying highp vec4 outCloud;

void main()
{
    gl_Position = mvp_matrix * vec4(position.x, position.y, position.z,1.0);
    
    outTexCoord = texCoord;
    outCloud = cloud;
}
