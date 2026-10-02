//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
//uniform highp float cloudMix;

varying highp vec2 outTexCoord;

void main()
{
   // highp vec4 tex = texture2D(texture, outTexCoord.xy);
    //highp float cloudVal = tex.g * 0.8;
    //highp vec4 texCloud = vec4(cloudVal,cloudVal,cloudVal,1.0);
    gl_FragColor = texture2D(texture, outTexCoord.xy);//mix(tex, texCloud, cloudMix);
}
