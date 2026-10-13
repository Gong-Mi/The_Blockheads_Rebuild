//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//


uniform sampler2D light_texture;
uniform highp vec4 daylight;

varying highp vec3 outTexCoord;

void main()
{
    highp vec4 lightTex = texture2D(light_texture, outTexCoord.xy);
    
    highp vec3 light = (lightTex.xyz + vec3(lightTex.w * daylight.r, lightTex.w * daylight.g, lightTex.w * daylight.b)) * 0.5;
    
    gl_FragColor = vec4(min(light, vec3(0.5,0.5,0.5)), 0.5) * daylight.a * (1.0 - step(0.99, min((1.0 - (lightTex.w)) * 32.0, 1.0))) * outTexCoord.z;
}
