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
varying lowp vec2 outTexCoordB;
varying lowp vec2 outLightTexCoord;
varying highp vec3 outLightNormal;

const highp mat3 tbnMat = mat3(vec3(1.0,0.0,0.0), vec3(0.0,1.0,0.0), vec3(0.0,0.0,-1.0));

void main()
{
    
    highp vec4 tex = texture2D(texture, outTexCoord);
    highp vec4 texB = texture2D(texture, outTexCoordB);
    highp vec4 lightTex = texture2D(light_texture, outLightTexCoord);
    highp vec4 destruct = texture2D(destruct_texture, outTexCoordB);
    highp vec4 destructEgg = texture2D(destruct_texture, outTexCoord);

    destruct.rgb = (destruct.rgb + destructEgg.rgb);
    
    highp float observedDayLight = lightTex.w * daylight.w;
    
    highp vec3 light = mix(lightTex.xyz, daylight.xyz / daylight.w, observedDayLight);


    highp vec3 normalMapValue = normalize(vec3((-destruct.r + 0.5),(destruct.g - 0.5),0.9));
    highp vec3 normalizedNormal = tbnMat * normalMapValue;
    
    highp float lightDP = dot(normalizedNormal, outLightNormal);
    
    highp float diffuse = max((lightDP + 0.4), 0.2);
    
    highp float specular = destruct.a * (pow(diffuse, 8.0 * destruct.a) * 0.15 + diffuse * 0.2);
    
    
    gl_FragColor = (tex * texB + vec4(vec3(specular), 0.0)) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0) * tex.a;
    
}
