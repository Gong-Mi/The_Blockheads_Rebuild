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
uniform lowp vec4 artificialLight;
uniform lowp vec4 daylight;

varying lowp vec2 outTexCoord;
varying highp vec3 outLightNormal;

void main()
{
    
    lowp vec4 tex = texture2D(texture, outTexCoord);
    highp vec4 destruct = texture2D(destruct_texture, outTexCoord);
    
    lowp float observedDayLight = artificialLight.w * daylight.w;
    
    lowp vec3 light = mix(artificialLight.xyz, daylight.xyz / daylight.w, observedDayLight);
    
    highp float lightDP = dot(normalize(outLightNormal + vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.0)), vec3(-0.3,0.5,0.2) * 2.0);
    lowp float diffuse = max(((lightDP + 0.2)), 0.2);
    lowp float specular = destruct.a * (0.5 + observedDayLight * 0.5) * diffuse;
    
    gl_FragColor = (tex + vec4(vec3(specular) * (light * 0.6 + vec3(0.6,0.6,0.6)), specular)) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0);
}
