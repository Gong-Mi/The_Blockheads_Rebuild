//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;

varying highp vec2 outTexCoord;
varying highp vec4 outLight;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord);
    
    gl_FragColor = tex* outLight;
}
