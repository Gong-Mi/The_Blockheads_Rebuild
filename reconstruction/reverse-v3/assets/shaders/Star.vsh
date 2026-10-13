//
//  Shader.vsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

attribute vec4 position;

uniform mat4 mvp_matrix;
uniform highp float color;

varying highp vec4 sizeOpacity;

void main()
{
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    highp float sizeOpacityFloat = pow((position.w * color) / 4.0, 2.0);
    sizeOpacity = vec4(sizeOpacityFloat,sizeOpacityFloat,sizeOpacityFloat,sizeOpacityFloat); 
    gl_PointSize = max(sizeOpacityFloat, 1.0);
}
