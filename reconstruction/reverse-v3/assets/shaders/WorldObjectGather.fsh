//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform sampler2D destruct_texture;
uniform highp vec4 light;
uniform highp float gatherOpacity;

varying highp vec2 outTexCoord;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord);
    highp float destructValue = texture2D(destruct_texture, outTexCoord).b;
    
    destructValue = clamp((gatherOpacity * 1.01 - destructValue) * 100.0, 0.0, 1.0);
    
    gl_FragColor = tex * light * destructValue;
}
