//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;


varying highp vec4 outTexCoord;


varying highp vec4 sizeOpacity;

void main()
{
    gl_FragColor = sizeOpacity;
}
