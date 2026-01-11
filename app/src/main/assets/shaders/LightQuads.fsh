//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform lowp float night_fraction;

varying lowp vec3 outTexCoord;
varying lowp vec4 outPaintColor; // 1.0 - luminosity is stored in alpha

void main()
{
    lowp vec4 tex = texture2D(texture, outTexCoord.xy);
    gl_FragColor = tex * outPaintColor * mix(1.0, night_fraction, outTexCoord.z);
}
