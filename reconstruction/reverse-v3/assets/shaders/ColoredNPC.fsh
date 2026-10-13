//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform highp vec4 light;
uniform highp vec4 npcColor;

varying highp vec4 outTexCoord;
varying highp float lighting;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);

    highp float mixv = abs(tex.r - 0.5) * 2.0;
    
    gl_FragColor = mix(npcColor, tex, mixv) * light * vec4(lighting,lighting,lighting * 0.9 + 0.1,1.0);
}