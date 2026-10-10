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
uniform sampler2D wing_texture;

uniform highp vec4 daylight;
uniform highp vec4 artificalLight;

varying highp vec4 outTexCoord;
varying highp vec3 outNormal;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    highp vec4 destruct = texture2D(destruct_texture, outTexCoord.xy);
    highp vec4 wings = texture2D(wing_texture, outTexCoord.zw);
    
    highp vec3 light = daylight.rgb + artificalLight.xyz;
    
    highp float lightDP = dot(normalize(outNormal + vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.0)), outLightNormal);
    highp float lightDPWings = dot(outNormal, outLightNormal);
    
    highp float diffuse = max((lightDP + 0.4), 0.2);
    highp float diffuseWings = max((lightDPWings + 0.4), 0.2);
    
    highp float specular = destruct.a * 2.0 * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);

    highp vec4 blockFinal = (tex + vec4(vec3(specular), 0.0)) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0);
    highp vec4 wingsFinal = wings * vec4(light * vec3(diffuseWings,diffuseWings,diffuseWings * 0.9 + 0.1), 1.0);

    gl_FragColor = vec4(mix(blockFinal.rgb, wingsFinal.rgb, wingsFinal.a), 1.0);
}
