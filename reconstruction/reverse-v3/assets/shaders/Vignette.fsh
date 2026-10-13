//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;


varying lowp vec2 outTexCoord;

void main()
{
   // highp vec4 tex = texture2D(texture, outTexCoord.xy);
    //highp float cloudVal = tex.g * 0.8;
    //highp vec4 texCloud = vec4(cloudVal,cloudVal,cloudVal,1.0);
    lowp float blackAlpha = length(outTexCoord.xy - vec2(0.5,0.5)) * 1.35;
    blackAlpha = blackAlpha * blackAlpha * blackAlpha;
    gl_FragColor =  vec4(0.0,0.0,0.0,blackAlpha);
}
