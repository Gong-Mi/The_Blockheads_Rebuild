//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform sampler2D texture;
uniform sampler2D textureB;
uniform highp vec4 daylight;
uniform highp vec4 artificalLight;
uniform highp vec4 skinColor;
uniform highp vec4 hairColor;

varying highp vec4 outTexCoord;
//varying highp float lighting;
varying highp float outDirectionalLight;
varying highp vec3 outNormal;
varying highp vec3 outLightNormal;

void main()
{
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    highp vec4 hairTex = texture2D(textureB, outTexCoord.xy);
    
    highp vec3 light = daylight.rgb + artificalLight.xyz * (outDirectionalLight + 0.5);
    
    highp float lightDP = dot(normalize(outNormal), normalize(outLightNormal));
    
    highp float diffuse = max((lightDP + 0.4), 0.2);
    
    highp float reflectivityModified = 0.3 * (1.0 - hairTex.r);
    
    highp float specular = reflectivityModified * (pow(diffuse, 12.0 * reflectivityModified) * 0.15 + diffuse * 0.2) * 0.5;
    
    highp vec4 baseWithoutHair = skinColor * (1.0 - tex.a) + tex;
    highp vec4 texCombined = mix(hairColor, baseWithoutHair, hairTex.r);
    
    
    gl_FragColor = (texCombined + vec4(vec3(specular), 0.0) * texCombined.a) * vec4(light * vec3(diffuse,diffuse,diffuse * 0.9 + 0.1), 1.0);
}
