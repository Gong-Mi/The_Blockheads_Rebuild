//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform sampler2D light_texture;
uniform sampler2D destruct_texture;
uniform lowp vec4 daylight;

varying lowp vec2 outTexCoord;
varying lowp vec2 outLightTexCoord;
varying highp vec3 outLightNormal;
varying highp vec3 outNormal;
varying highp vec4 outPaintColor; // 1.0 - luminosity is stored in alpha

void main()
{
    
    highp vec4 tex = texture2D(texture, outTexCoord);
    highp vec4 lightTex = texture2D(light_texture, outLightTexCoord);
    highp vec4 destruct = texture2D(destruct_texture, outTexCoord);
    
    highp float observedDayLight = lightTex.w * daylight.w;
    
    highp vec3 light = mix(lightTex.xyz, daylight.xyz / daylight.w, observedDayLight);
    
    highp float lightDP = dot(normalize(outNormal + vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.0)), outLightNormal);
    
    highp float diffuse = max((lightDP + 0.4), 0.2);
    
    highp float specular = destruct.a * 2.0 * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);
    
    
    gl_FragColor = (tex * (vec4(outPaintColor.xyz, 1.0)) + vec4(vec3(specular), 0.0)) * mix(vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0), vec4(1,1,1,1), 1.0 - outPaintColor.a);
    
}
