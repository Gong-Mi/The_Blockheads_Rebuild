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
uniform highp float progress;

varying highp vec2 outTexCoord;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord);
    
    highp float luma = (tex.r + tex.g + tex.b) * 0.33;
    
    highp float alpha = smoothstep(progress - 0.1, progress + 0.1, luma) * 0.5 + (1.0 - progress) * 0.5;
    
    gl_FragColor = mix(tex, vec4(1,1,1,1), alpha) * light;
}
