//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D cloud_texture;

uniform highp vec4 foregroundDayColor;
uniform highp vec4 backgroundDayColor;
varying highp vec4 outTexCoord;

void main()
{
    highp vec4 tex = texture2D(cloud_texture, outTexCoord.xy);
    highp vec4 outColor = mix(backgroundDayColor * tex.a, tex * foregroundDayColor, outTexCoord.z);
    gl_FragColor = outColor;
}
