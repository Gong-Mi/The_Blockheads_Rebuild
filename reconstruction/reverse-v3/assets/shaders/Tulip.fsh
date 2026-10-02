//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform highp vec4 black_color;
uniform highp vec4 white_color;

uniform highp vec4 light;

varying highp vec2 outTexCoord;

void main()
{
    lowp vec4 tex = texture2D(texture, outTexCoord);
    
    lowp float luma = tex.g;
    lowp float whiteAddition = max(luma - 0.8, 0.0);
    lowp vec4 tulipColor = mix(black_color, white_color, tex.r) * vec4(luma,luma,luma,tex.a) + vec4(whiteAddition, whiteAddition, whiteAddition, 0.0);
    
    gl_FragColor = tulipColor * light;
}
